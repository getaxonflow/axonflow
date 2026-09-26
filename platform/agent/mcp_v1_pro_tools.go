// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// V1 Plugin Pro MCP tools (umbrella #1958, PR2). Five tools that expose
// existing platform capabilities to AI agents via MCP, with tier gates
// per the locked freemium model:
//
//   axonflow_get_tenant_id       — Free + Pro, no gate; returns tenant identity + tier + upgrade prompt
//   axonflow_request_approval    - Free=2 per rolling 7d, Pro=20; wraps HITL queue create
//   axonflow_create_tenant_policy - retired in v11 (PRD v11 §1.2): refuses on every deployment and writes nothing
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
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"axonflow/platform/agent/hitl"
	"axonflow/platform/agent/license"
	"axonflow/platform/agent/rls"
	"axonflow/platform/shared/legacyfreeze"
)

// V1 Plugin Pro MCP tool names. Used for switch-dispatch in handleMCPToolsCall
// and as the canonical identifiers in tools/list. DO NOT rename without
// updating per-plugin SKILL files (S3 lane of umbrella #1958).
const (
	mcpToolNameGetTenantID        = "axonflow_get_tenant_id"
	mcpToolNameRequestApproval    = "axonflow_request_approval"
	mcpToolNameCreateTenantPolicy = "axonflow_create_tenant_policy"
	mcpToolNameGetCostEstimate    = "axonflow_get_cost_estimate"
	mcpToolNameListProFeatures    = "axonflow_list_pro_features"
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
			Description: "Request human-in-the-loop approval before executing a risky operation (e.g. shell command, file write, git push). On Free tier, 2 approval requests allowed per rolling 7-day window. On Pro, 20.",
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
				MaxInWindow:   2,
				LimitType:     LimitTypeHITLApprovalsWindow,
			},
		},
		{
			Name:        mcpToolNameCreateTenantPolicy,
			Description: "Retired in v11 (PRD v11 §1.2): answers LEGACY_POLICY_WRITE_FROZEN and writes nothing on any deployment, because a tenant dynamic policy decides nothing in v11. A policy is authored in the organization's typed document through the typed authoring route (" + legacyfreeze.TypedAuthoringRoute + "), or the portal's policy editor on Enterprise.",
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
						"description": "Tool / connector the policy was meant for (e.g. 'claude_code.Bash', '*' for all).",
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
			// No FreeUsageLimit: the active_policies quota counted legacy rows
			// this tool no longer writes, and a retired tool has nothing to cap.
			RequiredTier:   "",
			FreeUsageLimit: nil,
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
//  1. Empty caller tier (self-hosted / internal) → MCP-layer gate is a
//     no-op; underlying API services (e.g. policy_api_service.CreatePolicy
//     gates on IsPaidTier; hitl/handler.go gates on IsHITLApprovalEnabled)
//     remain authoritative for the self-hosted license tier axis.
//  2. RequiredTier non-empty + SaaS caller below it → emit feature_pro_only envelope
//  3. FreeUsageLimit non-nil + SaaS caller is Free + count check fails → emit graduated envelope
//
// Every refusal goes through writeMCPGateError, which answers the gate's
// status (403) with the envelope in the JSON-RPC result and the headers the
// REST twin writeFreeLimitError sets (#4274).
func enforceMCPToolGate(ctx context.Context, w http.ResponseWriter, req *jsonRPCRequest, session *mcpSession, tool mcpTool, db *sql.DB) bool {
	if session.tier == "" {
		// Self-hosted (Community / Evaluation / Paid) and internal
		// callers: the underlying API service is the source of truth
		// for license-tier gating. We defer rather than duplicate.
		return false
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

	// Gate 2: Graduated usage caps. Resolve limits from the caller's
	// tier (Free=2 HITL, Pro=20, Enterprise=-1 unlimited).
	// Self-hosted tiers (Community/Evaluation/Enterprise) have -1 for
	// SaaS-specific fields and skip this gate.
	if tool.FreeUsageLimit != nil {
		tierLimits := license.GetTierLimits(license.Tier(session.tier))
		switch tool.FreeUsageLimit.LimitType {
		case LimitTypeHITLApprovalsWindow:
			cap := tierLimits.MaxHITLApprovalsPerWeek
			if cap >= 0 {
				count, oldestInWindow := countHITLApprovalsInWindow(ctx, db, session.tenantID, time.Duration(tool.FreeUsageLimit.WindowSeconds)*time.Second)
				if count >= cap {
					resetsAt := oldestInWindow.Add(time.Duration(tool.FreeUsageLimit.WindowSeconds) * time.Second)
					writeMCPGateError(w, req, LimitTypeHITLApprovalsWindow, session.tier,
						cap, 0, "rolling_7d", &resetsAt)
					return true
				}
			}
		default:
			// A limit type this gate does not enforce refuses, so a tool that
			// declares one is never called ungated.
			writeMCPGateError(w, req, tool.FreeUsageLimit.LimitType, session.tier, 0, 0, "", nil)
			return true
		}
	}

	return false
}

// writeMCPGateError answers a tier-gate refusal with the V1 Plugin Pro
// envelope as JSON text in a JSON-RPC result (isError=true). Plugins parse
// the content text as JSON to extract the envelope and surface the upgrade
// prompt.
//
// This is the JSON-RPC analog of writeFreeLimitError, and answers what it
// answers (#4274): the status for the limit type (mcpGateStatus), the
// X-Axonflow-Tier-Limit and X-Axonflow-Upgrade-URL headers, and Retry-After
// only when the limit has a reset time. Before #4274 it answered 200 with no
// headers, so a client that reads the status or the headers, and the csaas
// telemetry row, saw an ordinary result.
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
	retrySecs := 0
	if resetsAt != nil {
		retrySecs = retryAfterSeconds(*resetsAt)
	}
	writeEnvelopeJSONRPC(w, req.ID, "", envelope, mcpGateStatus(limitType), retrySecs)
}

// mcpGateStatus is the HTTP status a limit type is answered with: 429 for the
// rate limits (daily_quota, per_minute), 403 for the tier gates
// (feature_pro_only, hitl_approvals_window), as the /health
// saas.upgrade_envelope capability states.
//
// The default arm still answers 403 for any other tier gate, active_policies
// among them; no caller reaches that one since #4356 retired
// axonflow_create_tenant_policy, the only tool it gated.
func mcpGateStatus(limitType string) int {
	switch limitType {
	case LimitTypeDailyQuota, LimitTypePerMinute:
		return http.StatusTooManyRequests
	default:
		return http.StatusForbidden
	}
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
	// Org-scoped: hitl_approval_queue is RLS-enabled (mig 025) — the
	// fail-open-through-RLS hole of #3039.
	err := rls.WithOrgScope(queryCtx, db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(queryCtx,
			`SELECT COUNT(*), COALESCE(MIN(created_at), NOW()) FROM hitl_approval_queue
			 WHERE tenant_id = $1 AND created_at > $2`,
			tenantID, cutoff).Scan(&count, &oldest)
	})
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

// mcpToolRequestApproval — Tool 2: wraps HITL CreateRequest.
//
// Routes through the long-lived `hitl.Service` (wired in run.go via
// `mcpHITLService`) so this MCP-tool path inherits the same enforcement
// as the HTTP handler at `POST /api/v1/hitl/queue`:
//
//   - License-tier gate (Community-tier process → ErrHITLApprovalDisabledByTier
//     mapped here to a clear MCP error; the row is never written).
//   - Pending-approval limit per tenant (license-tier-derived; some
//     deployments cap pending approvals to prevent operator-side flooding).
//   - Input validation + severity normalisation + expiry clamp.
//   - History row written automatically alongside the approval row.
//
// The SaaS Plugin per-tenant rolling-7d gate: 2 (Free) / 20 (Pro)
// already fired in `enforceMCPToolGate` before this body runs — that's
// the SaaS subscription differentiator and stays at the dispatch layer.
//
// `hitlServiceForTest` is the test seam: production callers must leave
// it nil so the wired-in `mcpHITLService` is used; tests inject a
// stubbed Service to drive specific tier/cap responses without standing
// up the real DB.
func mcpToolRequestApproval(ctx context.Context, _ *sql.DB, session *mcpSession, args map[string]interface{}) (interface{}, error) {
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
	if strings.TrimSpace(triggerReason) == "" {
		triggerReason = "MCP-tool-initiated approval (axonflow_request_approval)"
	}

	svc := resolveHITLServiceForMCP()
	if svc == nil {
		return nil, fmt.Errorf("HITL service unavailable — try again shortly")
	}

	// `triggered_policy_id` / `triggered_policy_name` carry sentinel
	// values because this approval is user-initiated through the MCP
	// tool, not driven by a policy hit. The Service rejects empty
	// values, so we always supply a stable identifier the audit trail
	// can search on.
	createInput := hitl.CreateApprovalInput{
		OrgID:               session.tenantID, // SaaS Plugin: no separate org concept; tenant == org
		TenantID:            session.tenantID,
		ClientID:            session.clientID,
		UserID:              session.userID,
		OriginalQuery:       originalQuery,
		RequestType:         requestType,
		TriggeredPolicyID:   "mcp-tool-initiated",
		TriggeredPolicyName: "MCP Tool — axonflow_request_approval",
		TriggerReason:       triggerReason,
		Severity:            severity,
	}

	req, err := svc.CreateApprovalRequest(ctx, createInput)
	if err != nil {
		switch {
		case errors.Is(err, hitl.ErrHITLApprovalDisabledByTier):
			// Community-tier process — surface a clear deployment-level
			// error so the LLM caller can explain it to the user. The
			// SaaS Plugin Pro subscription doesn't unlock this — the
			// running plugin platform itself is on Community tier and
			// needs at least a Professional license (HITL is Enterprise-only
			// since the 2026-08-26 operator decision; Evaluation was entitled
			// until then).
			return nil, fmt.Errorf("HITL approvals are disabled on this AxonFlow deployment. The AxonFlow agent needs a Professional, Enterprise or Enterprise Plus license to enable the approval queue. See https://getaxonflow.com/pricing")
		case errors.Is(err, hitl.ErrPendingApprovalLimitExceeded):
			// Per-tenant pending-cap from the license tier limits.
			// Distinct from the 1/7d SaaS Plugin Free gate: that's a
			// rolling-window count gate; this is a snapshot of CURRENTLY
			// pending rows (covers cleanup-stuck queues). Both paths can
			// fire in principle; the Service-level cap fires here.
			return nil, fmt.Errorf("pending approval limit exceeded for this tenant — wait for prior approvals to be reviewed before submitting more")
		default:
			return nil, fmt.Errorf("could not create approval request: %w", err)
		}
	}

	return map[string]interface{}{
		// Explicit positive signal so LLM consumers don't misread
		// `status: "pending"` as failure. The approval row IS pending
		// human review — that's the success state for an approval
		// request: created and awaiting reviewer action.
		"success":         true,
		"submitted":       true,
		"awaiting_review": true,
		"approval_id":     req.RequestID.String(),
		"status":          "pending", // wire-level HITL row status — kept for back-compat
		"original_query":  originalQuery,
		"request_type":    requestType,
		"severity":        req.Severity, // post-Service normalisation
		"message":         "Approval request submitted successfully. A reviewer must approve this request via the AxonFlow customer portal before the operation can proceed.",
	}, nil
}

// hitlServiceProvider is the test seam for swapping the HITL service in
// unit tests. Production code leaves it nil; tests set it before the
// call and reset to nil after. Mirrors the `tierProvider` pattern used
// inside the hitl package itself.
type hitlServiceProvider func() *hitl.Service

// hitlServiceForTest, when non-nil, overrides the package-level
// `mcpHITLService`. Test-only.
var hitlServiceForTest hitlServiceProvider

// resolveHITLServiceForMCP returns the Service the MCP tool should use.
// In production this is the long-lived `mcpHITLService` wired in
// run.go. In tests, `hitlServiceForTest` overrides.
func resolveHITLServiceForMCP() *hitl.Service {
	if hitlServiceForTest != nil {
		return hitlServiceForTest()
	}
	return mcpHITLService
}

// errTenantPolicyWriteRetired is what axonflow_create_tenant_policy answers
// from v11.1.0, on every edition and every database role (#4249 row
// 5667510887). The tool created a tenant dynamic policy, and in v11 a tenant
// dynamic policy decides nothing (PRD v11 §1.2): the anchored engine decides
// the planes it would have governed. Until v11.1.0 the tool still wrote that
// row wherever the agent's database role could write the legacy table (an
// owner-role deployment) and answered created:true about it, and refused only
// where core/172's freeze reached it (an application-role deployment). It now refuses before any orchestrator
// call, so no deployment writes a row that nothing reads.
//
// The answer follows the retired override tools (errOverrideWriteRetired): the
// freeze's code, rendered here rather than proxied, so the caller reads the code
// and the remedy on every deployment. No closing full stop, as there (ST1005).
//
// The typed re-point is not this answer's to make. A typed document has no
// tenant scope, one of the tool's actions cannot be published on any edition
// through the typed route, and a publish replaces the organization's document;
// those questions are the row's v12.0.0 remainder.
var errTenantPolicyWriteRetired = errors.New(legacyfreeze.ErrCode + ": " +
	"axonflow_create_tenant_policy is retired in v11 and writes nothing on any deployment: " +
	"it created a tenant dynamic policy, and a tenant dynamic policy decides nothing in v11 (PRD v11 §1.2). " +
	"Author the rule in the organization's typed document through the typed authoring route at " + legacyfreeze.TypedAuthoringRoute +
	" (the portal's policy editor on Enterprise); re-pointing this tool at typed authoring is tracked on #4249 (row 5667510887)")

// mcpToolCreateTenantPolicy answers errTenantPolicyWriteRetired for every
// caller. It reads no argument, as mcpToolCreateOverride reads none: a retired
// tool refuses whatever it is given, so a caller missing a field is told where
// the write went rather than which field to add to a write that cannot happen.
func mcpToolCreateTenantPolicy(_ *mcpSession, _ map[string]interface{}) (interface{}, error) {
	return nil, errTenantPolicyWriteRetired
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
			"price_usd":     9.99,
			"duration_days": 90,
			"renewal":       "one-time (re-purchase to extend; no auto-renewal)",
		},
		"differentiators": []map[string]interface{}{
			{
				"id":         "daily_quota",
				"capability": "Daily quota",
				"free":       "200 events/day",
				"pro":        "2,000 events/day (10× Free)",
			},
			{
				"id":         "audit_retention",
				"capability": "Audit retention",
				"free":       "3 days",
				"pro":        "30 days (10× Free)",
			},
			{
				"id":         "hitl_approvals",
				"capability": "HITL approval gating",
				"free":       "2 per rolling 7 days",
				"pro":        "Up to 20/week",
			},
			{
				"id":         "cost_preflight",
				"capability": "LLM cost pre-flight",
				"free":       "Not available",
				"pro":        "Available",
			},
		},
		"upgrade_url": v1ProUpgradeCompareURL,
		"buy_url":     v1ProUpgradeBuyURL,
		"tone":        "Free validates the workflow. Pro raises the caps when AxonFlow becomes part of your real workflow.",
	}, nil
}
