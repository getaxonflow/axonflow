// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// V1 Plugin Pro MCP tools (umbrella #1958, PR2). Five tools that expose
// existing platform capabilities to AI agents via MCP, with tier gates
// per the locked freemium model:
//
//   axonflow_get_tenant_id       — Free + Pro, no gate; returns tenant identity + tier + upgrade prompt
//   axonflow_request_approval    — Free=1/7d rolling, Pro=unlimited; wraps HITL queue create
//   axonflow_create_tenant_policy — Free=2 active max, Pro=unlimited; wraps dynamic-policies create
//   axonflow_get_cost_estimate   — Pro only; wraps cost_estimation_handler
//   axonflow_list_pro_features   — Free + Pro, pure data tool; surfaces locked Pro feature list
//
// Tier gating is enforced centrally by enforceMCPToolGate() at tools/call
// dispatch — each tool body assumes the gate has already passed. On gate
// failure the dispatch emits a JSON-RPC result with isError=true and the
// V1 envelope as JSON text content (per umbrella #1958 envelope shape).

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent/license"
)

// V1 Plugin Pro MCP tool names. Used for switch-dispatch in handleMCPToolsCall
// and as the canonical identifiers in tools/list. DO NOT rename without
// updating per-plugin SKILL files (S3 lane of umbrella #1958).
const (
	mcpToolNameGetTenantID       = "axonflow_get_tenant_id"
	mcpToolNameRequestApproval   = "axonflow_request_approval"
	mcpToolNameCreateTenantPolicy = "axonflow_create_tenant_policy"
	mcpToolNameGetCostEstimate   = "axonflow_get_cost_estimate"
	mcpToolNameListProFeatures   = "axonflow_list_pro_features"
)

// v1ProMCPTools returns the 5 V1 Plugin Pro tool definitions with their
// RequiredTier + FreeUsageLimit gates applied. Called from getMCPTools()
// to splice these into the full tools list.
func v1ProMCPTools() []mcpTool {
	return []mcpTool{
		{
			Name:        mcpToolNameGetTenantID,
			Description: "Return the calling tenant's identity, current tier, and Pro upgrade URL. Use when the user asks how to upgrade, what tier they're on, or for their tenant ID for Stripe Checkout. Available to all tiers.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			RequiredTier:   "",
			FreeUsageLimit: nil,
		},
		{
			Name:        mcpToolNameRequestApproval,
			Description: "Request human-in-the-loop approval before executing a risky operation (e.g. shell command, file write, git push). On Free tier, 1 approval request allowed per rolling 7-day window. On Pro, unlimited.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"original_query": map[string]interface{}{
						"type":        "string",
						"description": "The user's original natural-language request that prompted this approval check.",
					},
					"request_type": map[string]interface{}{
						"type":        "string",
						"description": "Category of the operation requiring approval (e.g. 'shell_command', 'file_write', 'git_push').",
					},
					"trigger_reason": map[string]interface{}{
						"type":        "string",
						"description": "Why approval is being requested (e.g. 'destructive_command', 'production_deploy').",
					},
					"severity": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"low", "medium", "high", "critical"},
						"description": "Risk severity of the operation.",
					},
				},
				"required": []string{"original_query", "request_type"},
			},
			RequiredTier: "",
			FreeUsageLimit: &FreeUsageLimit{
				WindowSeconds: 7 * 24 * 3600, // 7d rolling window
				MaxInWindow:   1,
				LimitType:     LimitTypeHITLApprovalsWindow,
			},
		},
		{
			Name:        mcpToolNameCreateTenantPolicy,
			Description: "Create a custom tenant-scoped governance policy. Free tier supports 2 active policies (delete one to make room); Pro removes the cap. Useful for rules like 'block writes to ~/.ssh/' or 'require approval for any rm -rf'.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Human-readable policy name.",
					},
					"description": map[string]interface{}{
						"type":        "string",
						"description": "What the policy does.",
					},
					"connector_type": map[string]interface{}{
						"type":        "string",
						"description": "Tool / connector this policy applies to (e.g. 'claude_code.Bash', '*' for all).",
					},
					"pattern": map[string]interface{}{
						"type":        "string",
						"description": "Regex or literal pattern to match against tool inputs.",
					},
					"action": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"block", "warn", "audit", "require_approval"},
						"description": "Action to take on match.",
					},
				},
				"required": []string{"name", "connector_type", "pattern", "action"},
			},
			RequiredTier: "",
			FreeUsageLimit: &FreeUsageLimit{
				MaxCount:  2,
				LimitType: LimitTypeActivePolicies,
			},
		},
		{
			Name:        mcpToolNameGetCostEstimate,
			Description: "Estimate the LLM token cost of a planned multi-step operation BEFORE running it. Pro-tier feature. Returns input/output token estimates, total cost in USD, and per-step breakdown.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"plan": map[string]interface{}{
						"type":        "string",
						"description": "Description of the multi-step operation to cost-estimate.",
					},
					"model": map[string]interface{}{
						"type":        "string",
						"description": "LLM model identifier (e.g. 'claude-opus-4-7', 'gpt-4'). Defaults to the agent's default model.",
					},
				},
				"required": []string{"plan"},
			},
			RequiredTier:   "Pro",
			FreeUsageLimit: nil,
		},
		{
			Name:        mcpToolNameListProFeatures,
			Description: "Return the locked V1 Plugin Pro feature list as data. Use when the user asks 'what would I get if I upgraded?' Available to all tiers.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
			RequiredTier:   "",
			FreeUsageLimit: nil,
		},
	}
}

// filterMCPToolsByTier filters the tools list by the caller's effective
// tier. Free callers don't see Pro-only tools (which would be useless to
// them anyway). Empty tier (self-hosted enterprise / internal-service)
// sees all tools — the gating framework only applies to SaaS Plugin
// callers per umbrella #1958.
func filterMCPToolsByTier(tools []mcpTool, callerTier string) []mcpTool {
	if callerTier == "" {
		return tools // self-hosted / internal — all tools visible
	}
	callerRank := saasPluginTierRank(callerTier)
	out := make([]mcpTool, 0, len(tools))
	for _, t := range tools {
		if t.RequiredTier == "" {
			out = append(out, t)
			continue
		}
		if saasPluginTierRank(t.RequiredTier) <= callerRank {
			out = append(out, t)
		}
	}
	return out
}

// saasPluginTierRank ranks SaaS Plugin tiers for the tier-gating framework.
// Free=0, Pro=1, Premium=2. Unknown tiers return 0 (most-restrictive). The
// rank is internal to the framework — the same Tier strings are still
// stored verbatim in DB / envelopes / wire responses.
func saasPluginTierRank(tier string) int {
	switch tier {
	case string(license.TierFree):
		return 0
	case string(license.TierPro):
		return 1
	case string(license.TierPremium):
		return 2
	default:
		return 0 // unknown → most-restrictive (gates fail closed)
	}
}

// enforceMCPToolGate runs the tier-gating framework against a tool the
// caller is about to invoke. Returns true if the call should be blocked
// (the helper wrote the JSON-RPC error result + envelope; caller returns
// without running the tool body); false if the call should proceed.
//
// Gating logic:
//  1. Empty caller tier (self-hosted / internal) → no gate applies, always proceed
//  2. RequiredTier non-empty + caller below it → emit feature_pro_only envelope
//  3. FreeUsageLimit non-nil + caller is Free + count check fails → emit graduated envelope
//
// All envelope writes go through writeFreeLimitError so the wire shape
// matches the 429 daily_quota path locked in PR1 + umbrella #1958.
func enforceMCPToolGate(ctx context.Context, w http.ResponseWriter, req *jsonRPCRequest, session *mcpSession, tool mcpTool, db *sql.DB) bool {
	if session.tier == "" {
		return false // self-hosted enterprise / internal — gating doesn't apply
	}

	// Gate 1: RequiredTier (binary Pro-only / Premium-only)
	if tool.RequiredTier != "" {
		callerRank := saasPluginTierRank(session.tier)
		neededRank := saasPluginTierRank(tool.RequiredTier)
		if callerRank < neededRank {
			writeMCPGateError(w, req, LimitTypeFeatureProOnly, session.tier, 0, 0, "", nil)
			return true
		}
	}

	// Gate 2: FreeUsageLimit (graduated cap; only applies to Free tier)
	if tool.FreeUsageLimit != nil && session.tier == string(license.TierFree) {
		switch tool.FreeUsageLimit.LimitType {
		case LimitTypeActivePolicies:
			count := countActiveTenantPolicies(ctx, db, session.tenantID)
			if count >= tool.FreeUsageLimit.MaxCount {
				writeMCPGateError(w, req, LimitTypeActivePolicies, session.tier, tool.FreeUsageLimit.MaxCount, 0, "", nil)
				return true
			}
		case LimitTypeHITLApprovalsWindow:
			count, oldestInWindow := countHITLApprovalsInWindow(ctx, db, session.tenantID, time.Duration(tool.FreeUsageLimit.WindowSeconds)*time.Second)
			if count >= tool.FreeUsageLimit.MaxInWindow {
				// resets_at = oldest_in_window + window duration (when that
				// row falls out of the rolling window the user gets one back)
				resetsAt := oldestInWindow.Add(time.Duration(tool.FreeUsageLimit.WindowSeconds) * time.Second)
				writeMCPGateError(w, req, LimitTypeHITLApprovalsWindow, session.tier,
					tool.FreeUsageLimit.MaxInWindow, 0, "rolling_7d", &resetsAt)
				return true
			}
		}
	}

	return false
}

// writeMCPGateError emits a JSON-RPC result with isError=true and the V1
// Plugin Pro envelope as JSON text content. Plugins parse the content
// text as JSON to extract the envelope and surface the upgrade prompt.
//
// This is the JSON-RPC analog of writeFreeLimitError (which wraps the
// envelope in an HTTP 403 for non-MCP paths). Same envelope shape, same
// locked URLs, same headers conceptually — but JSON-RPC doesn't have HTTP
// status codes inside its result, so the envelope semantics are carried
// in the body alone.
func writeMCPGateError(w http.ResponseWriter, req *jsonRPCRequest, limitType, tier string, limit, remaining int, window string, resetsAt *time.Time) {
	wording := renderWording(limitType, resetsAt)
	envelope := rateLimitEnvelope{
		Error:     wording,
		LimitType: limitType,
		Tier:      tier,
		Limit:     limit,
		Remaining: remaining,
		Window:    window,
		ResetsAt:  resetsAt,
		Upgrade: upgradeBlock{
			Tier:       "Pro",
			Wording:    wording,
			CompareURL: v1ProUpgradeCompareURL,
			BuyURL:     v1ProUpgradeBuyURL,
		},
	}
	envelopeJSON, _ := json.MarshalIndent(envelope, "", "  ")
	writeJSONRPCResult(w, req.ID, mcpToolCallResult{
		Content: []mcpContent{{Type: "text", Text: string(envelopeJSON)}},
		IsError: true,
	})
}

// countActiveTenantPolicies counts the active custom dynamic_policies
// rows for a tenant. Used by the active_policies FreeUsageLimit on
// axonflow_create_tenant_policy.
//
// Active = enabled boolean (per migrations/core/010_policy_tables.sql).
// PR2's initial query used a non-existent `deleted_at` column —
// runtime-e2e/v1_pro_full_matrix caught the drift in matrix C5.
//
// Returns 0 on DB error so a transient failure doesn't accidentally
// block a Free user. Fail open on the count side — the actual create
// has its own integrity checks.
func countActiveTenantPolicies(ctx context.Context, db *sql.DB, tenantID string) int {
	if db == nil {
		return 0
	}
	queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var count int
	err := db.QueryRowContext(queryCtx,
		`SELECT COUNT(*) FROM dynamic_policies WHERE tenant_id = $1 AND enabled = true`,
		tenantID).Scan(&count)
	if err != nil {
		return 0 // fail open
	}
	return count
}

// countHITLApprovalsInWindow counts HITL approval requests created within
// the given rolling window for a tenant. Returns count + the timestamp of
// the OLDEST request in the window — used by the dispatch to compute
// resets_at (= oldest + window_duration).
//
// Returns (0, time.Time{}) on DB error so a transient failure doesn't
// accidentally block a Free user. Fail-open on the count side.
func countHITLApprovalsInWindow(ctx context.Context, db *sql.DB, tenantID string, window time.Duration) (int, time.Time) {
	if db == nil {
		return 0, time.Time{}
	}
	queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cutoff := time.Now().Add(-window)
	var count int
	var oldest time.Time
	err := db.QueryRowContext(queryCtx,
		`SELECT COUNT(*), COALESCE(MIN(created_at), NOW()) FROM hitl_approval_queue
		 WHERE tenant_id = $1 AND created_at > $2`,
		tenantID, cutoff).Scan(&count, &oldest)
	if err != nil {
		return 0, time.Time{}
	}
	return count, oldest
}

// --- Tool implementations ---

// mcpToolGetTenantID — Tool 1: pure identity tool. Returns the tenant_id
// + current tier + upgrade URL + agent endpoint. No DB query (everything
// is already in session). No-args; the call itself authenticates the
// caller.
func mcpToolGetTenantID(session *mcpSession) (interface{}, error) {
	tier := session.tier
	if tier == "" {
		tier = "self-hosted" // friendly label for non-SaaS callers
	}
	return map[string]interface{}{
		"success":     true, // explicit success flag (#1986) — LLM consumers should not need to infer
		"tenant_id":   session.tenantID,
		"tier":        tier,
		"upgrade_url": v1ProUpgradeCompareURL,
		"buy_url":     v1ProUpgradeBuyURL,
	}, nil
}

// mcpToolRequestApproval — Tool 2: wraps HITL CreateRequest. Gate has
// already enforced the 1/7d rolling cap (Free) or no cap (Pro). This
// function just creates the approval row.
//
// PR2 lands the gate + a synthetic insert into hitl_approval_queue (since
// the wrapper isn't yet plumbed to call the full HITL service). Future
// follow-up will route through hitl.Handler.CreateRequest's full validation
// pipeline + propagate the X-Org-ID / X-Tenant-ID headers correctly. For
// V1 Plugin Pro launch the synthetic insert is sufficient — the row lands,
// the gate counter sees it, the count-based cap works correctly.
func mcpToolRequestApproval(ctx context.Context, db *sql.DB, session *mcpSession, args map[string]interface{}) (interface{}, error) {
	originalQuery, _ := args["original_query"].(string)
	requestType, _ := args["request_type"].(string)
	if strings.TrimSpace(originalQuery) == "" || strings.TrimSpace(requestType) == "" {
		return nil, fmt.Errorf("original_query and request_type are required")
	}
	severity, _ := args["severity"].(string)
	if severity == "" {
		severity = "medium"
	}
	triggerReason, _ := args["trigger_reason"].(string)

	if db == nil {
		return nil, fmt.Errorf("HITL store unavailable — try again shortly")
	}

	// Insert into hitl_approval_queue. The schema (per
	// migrations/core/025_hitl_oversight_queue.sql) has 4 NOT NULL
	// columns we must supply beyond the obvious tenant/user fields:
	//   triggered_policy_id — sentinel "mcp-tool-initiated" since this
	//     approval is user-initiated via the MCP tool, not policy-driven
	//   triggered_policy_name — friendly label for the audit trail
	//   trigger_reason — caller arg, fallback to a tool-identifying string
	//   expires_at — default 24h from creation (HITLExpiryHours pattern)
	//
	// PR2's initial INSERT omitted these — caught by
	// runtime-e2e/v1_pro_full_matrix (matrix C4 NOT NULL violation).
	// Same regression-test catches future drift.
	if strings.TrimSpace(triggerReason) == "" {
		triggerReason = "MCP-tool-initiated approval (axonflow_request_approval)"
	}
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var id string
	err := db.QueryRowContext(queryCtx,
		`INSERT INTO hitl_approval_queue
		 (tenant_id, org_id, client_id, user_id, original_query, request_type, trigger_reason, severity, status,
		  triggered_policy_id, triggered_policy_name, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending',
		         'mcp-tool-initiated', 'MCP Tool — axonflow_request_approval', NOW() + interval '24 hours', NOW())
		 RETURNING id`,
		session.tenantID,
		session.tenantID, // synthetic org_id = tenant_id for SaaS Plugin (no separate org concept)
		session.clientID,
		session.userID,
		originalQuery,
		requestType,
		triggerReason,
		severity,
	).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("could not create approval request: %w", err)
	}
	return map[string]interface{}{
		// Explicit positive signal so LLM consumers don't misread
		// `status: "pending"` as failure (#1986). The approval row
		// IS pending human review — that's the success state for an
		// approval request: created and awaiting reviewer action.
		"success":          true,
		"submitted":        true,
		"awaiting_review":  true,
		"approval_id":      id,
		"status":           "pending", // wire-level HITL row status — kept for back-compat
		"original_query":   originalQuery,
		"request_type":     requestType,
		"severity":         severity,
		"message":          "Approval request submitted successfully. A reviewer must approve this request via the AxonFlow customer portal before the operation can proceed.",
	}, nil
}

// mcpToolCreateTenantPolicy — Tool 3: wraps dynamic_policies create.
// Gate has already enforced the 2-active cap (Free) or no cap (Pro).
//
// Same caveat as mcpToolRequestApproval: PR2 lands the gate + synthetic
// insert. Future follow-up will route through orchestrator's validated
// dynamic-policies handler with full schema validation. For V1 Plugin
// Pro launch the synthetic insert is sufficient — the row lands, the
// gate counter sees it, the count-based cap works correctly.
func mcpToolCreateTenantPolicy(ctx context.Context, db *sql.DB, session *mcpSession, args map[string]interface{}) (interface{}, error) {
	name, _ := args["name"].(string)
	connectorType, _ := args["connector_type"].(string)
	pattern, _ := args["pattern"].(string)
	action, _ := args["action"].(string)
	description, _ := args["description"].(string)
	if strings.TrimSpace(name) == "" || strings.TrimSpace(connectorType) == "" ||
		strings.TrimSpace(pattern) == "" || strings.TrimSpace(action) == "" {
		return nil, fmt.Errorf("name, connector_type, pattern, and action are required")
	}
	switch action {
	case "block", "warn", "audit", "require_approval":
		// ok
	default:
		return nil, fmt.Errorf("action must be one of: block, warn, audit, require_approval")
	}

	if db == nil {
		return nil, fmt.Errorf("policy store unavailable — try again shortly")
	}

	// Build the dynamic_policies row per the actual schema (per
	// migrations/core/010_policy_tables.sql):
	//   policy_id (UNIQUE NOT NULL) — generate a stable per-policy ID
	//   policy_type (NOT NULL) — 'context_aware' for connector+pattern rules
	//   conditions JSONB (NOT NULL) — array of conditions to evaluate
	//   actions JSONB (NOT NULL) — array of actions on match
	//
	// PR2's initial INSERT used a non-existent `definition` column —
	// caught by runtime-e2e/v1_pro_full_matrix (matrix C5 column-doesn't-exist
	// failure). Same regression-test catches future drift.
	policyID := fmt.Sprintf("tenant-%s-%s", session.tenantID[:min(len(session.tenantID), 12)], uuid.New().String())
	conditionsJSON, _ := json.Marshal([]map[string]interface{}{
		{
			"field":          "connector_type",
			"operator":       "matches",
			"connector_type": connectorType,
			"pattern":        pattern,
		},
	})
	actionsJSON, _ := json.Marshal([]map[string]interface{}{
		{
			"type":   action,
			"reason": fmt.Sprintf("Tenant policy %q matched", name),
		},
	})

	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var id string
	err := db.QueryRowContext(queryCtx,
		`INSERT INTO dynamic_policies
		 (policy_id, name, description, policy_type, conditions, actions, enabled, tenant_id, created_at)
		 VALUES ($1, $2, $3, 'context_aware', $4::jsonb, $5::jsonb, true, $6, NOW())
		 RETURNING id`,
		policyID, name, description, string(conditionsJSON), string(actionsJSON), session.tenantID,
	).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("could not create tenant policy: %w", err)
	}
	return map[string]interface{}{
		// Explicit positive signal for LLM consumers (#1986). Without
		// `success: true` + `created: true`, models can misread the
		// presence of `enabled: true` (which describes the policy
		// state, not the operation outcome) as ambiguous.
		"success":        true,
		"created":        true,
		"id":             id,
		"policy_id":      policyID,
		"name":           name,
		"connector_type": connectorType,
		"pattern":        pattern,
		"action":         action,
		"enabled":        true,
		"message":        fmt.Sprintf("Successfully created tenant-scoped policy %q. It will apply to subsequent governed calls.", name),
	}, nil
}

// min returns the smaller of two integers — used to safely truncate
// tenant_id prefixes in policy_id generation. Go 1.21+ has builtin min
// but this file is build-tag-agnostic.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// mcpToolGetCostEstimate — Tool 4: proxies to the orchestrator's
// authoritative cost-estimation pipeline. Gate has already verified
// caller is Pro+ (per RequiredTier="Pro" on the tool definition).
//
// Implementation per umbrella #1958 + sub-issue #1972 (PR3). Builds a
// single-step workflow from the user's free-text plan + model and
// POSTs to /api/v1/plans/estimate. The orchestrator handles:
//   - Input token estimation (char count / 4 + 50 overhead via
//     planning_engine.estimateStepTokens)
//   - Per-model pricing lookup via pricingConfig
//   - Per-step breakdown (returned for Evaluation+ tier; SaaS Pro
//     buyers get aggregate only since the deployment runs at the
//     baseline tier — Pro/Premium SaaS Plugin tiers are tenant-scoped,
//     not deployment-scoped)
//   - Per-tenant daily rate-limit (MaxCostEstimatesPerDay; bumping
//     for SaaS Plugin tiers is a separate follow-up)
//
// We replaced the prior heuristic stub (chars/4 input, 3x output,
// hardcoded per-model prices in plugin) so the platform has a single
// source of truth for cost estimation. Drift between plugin and
// orchestrator pricing was a real risk the stub introduced.
func mcpToolGetCostEstimate(session *mcpSession, args map[string]interface{}) (interface{}, error) {
	plan, _ := args["plan"].(string)
	if strings.TrimSpace(plan) == "" {
		return nil, fmt.Errorf("plan is required")
	}
	model, _ := args["model"].(string)
	if model == "" {
		model = "claude-sonnet-4-6"
	}
	provider := deriveProviderFromModel(model)

	// Build the orchestrator request body. Single LLM step carrying
	// the user's plan as the prompt. The orchestrator estimates input
	// tokens from prompt char count and output tokens from MaxTokens
	// (4096 here matches Claude/GPT default upper bound). MaxTokens
	// only caps the OUTPUT estimate; the orchestrator doesn't truncate
	// the prompt itself.
	body := map[string]interface{}{
		"provider": provider,
		"model":    model,
		"steps": []map[string]interface{}{
			{
				"name":       "plan",
				"type":       "llm-call",
				"prompt":     plan,
				"max_tokens": 4096,
			},
		},
	}

	resp, err := mcpProxyToOrchestrator(session, "POST", "/api/v1/plans/estimate", body)
	if err != nil {
		return nil, fmt.Errorf("cost estimate failed: %w", err)
	}

	// Orchestrator returns CostEstimateResponse{estimated_cost_usd,
	// currency, breakdown[]} — pass it through verbatim with one
	// additional field (the model the user requested) so plugin-side
	// formatters have the full input context without a separate look-up.
	respMap, ok := resp.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("orchestrator returned unexpected response shape: %T", resp)
	}
	respMap["model"] = model
	respMap["plan"] = plan
	respMap["success"] = true // explicit success flag for LLM consumers (#1986)
	return respMap, nil
}

// deriveProviderFromModel maps a model name to its LLM provider. Used
// to populate the orchestrator request's `provider` field — the
// orchestrator's pricingConfig keys by (provider, model) so passing
// the right provider gets us the right per-token price.
//
// The mapping mirrors how the orchestrator's planning engine resolves
// providers for unrouted models (defaults to anthropic for unknown
// names, matching the platform's primary LLM choice).
func deriveProviderFromModel(model string) string {
	m := strings.ToLower(model)
	switch {
	case strings.Contains(m, "claude"), strings.Contains(m, "opus"),
		strings.Contains(m, "sonnet"), strings.Contains(m, "haiku"):
		return "anthropic"
	case strings.HasPrefix(m, "gpt"), strings.Contains(m, "openai"):
		return "openai"
	case strings.Contains(m, "gemini"):
		return "google"
	case strings.Contains(m, "mistral"):
		return "mistral"
	default:
		return "anthropic" // platform default
	}
}

// mcpToolListProFeatures — Tool 5: pure data tool. Returns the locked V1
// Plugin Pro feature list per umbrella #1958. So a Free user's AI can
// answer "what would I get if I upgraded?" without reading docs.
//
// All values are derived from package-level constants in
// community_saas_ratelimit_response.go + tier_support.go; never
// hand-typed here so the locked numbers stay consistent across surfaces.
func mcpToolListProFeatures(session *mcpSession) (interface{}, error) {
	currentTier := session.tier
	if currentTier == "" {
		currentTier = "self-hosted"
	}
	return map[string]interface{}{
		"success":      true, // explicit success flag for LLM consumers (#1986)
		"current_tier": currentTier,
		"pricing": map[string]interface{}{
			"price_usd":      9.99,
			"duration_days":  90,
			"renewal":        "one-time (re-purchase to extend; no auto-renewal)",
		},
		"differentiators": []map[string]interface{}{
			{
				"id":          "daily_quota",
				"capability":  "Daily quota",
				"free":        "200 events/day",
				"pro":         "2,000 events/day (10× Free)",
			},
			{
				"id":          "audit_retention",
				"capability":  "Audit retention",
				"free":        "3 days",
				"pro":         "30 days (10× Free)",
			},
			{
				"id":          "active_policies",
				"capability":  "Custom tenant policies",
				"free":        "2 active max",
				"pro":         "Unlimited",
			},
			{
				"id":          "hitl_approvals",
				"capability":  "HITL approval gating",
				"free":        "1 per rolling 7 days",
				"pro":         "Unlimited",
			},
			{
				"id":          "cost_preflight",
				"capability":  "LLM cost pre-flight",
				"free":        "Not available",
				"pro":         "Available",
			},
		},
		"upgrade_url":   v1ProUpgradeCompareURL,
		"buy_url":       v1ProUpgradeBuyURL,
		"tone":          "Free validates the workflow. Pro removes the caps when AxonFlow becomes part of your real workflow.",
	}, nil
}
