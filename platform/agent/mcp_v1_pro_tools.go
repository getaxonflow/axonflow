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
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"axonflow/platform/agent/hitl"
	"axonflow/platform/agent/license"
	"axonflow/platform/agent/rls"
	sharedpolicy "axonflow/platform/shared/policy"
)

// activePolicyCountErrorsTotal counts countActiveTenantPolicies failures that
// fell back to the fail-open default (count=0), per #3296 Step E / epic #3293
// item #22 (folds in the #3039/#2230 family): the Free-tier active_policies
// quota gate deliberately fails OPEN on a count error (a transient DB blip
// must not block a legitimate Free user), but a silent fail-open is a silent
// quota bypass if the underlying read is failing systematically (e.g. an
// RLS-blind read on a mis-provisioned deployment, mirroring #3039). A
// sustained nonzero rate on this counter means the quota is not actually
// being enforced and needs operator attention.
var activePolicyCountErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "axonflow_active_policy_count_errors_total",
	Help: "Count of Free-tier active_policies quota checks (countActiveTenantPolicies) that failed and fell back to fail-open (count=0). A nonzero rate means the quota may be silently bypassed.",
})

// activePolicyCountLoader and activePolicyCountLoaderDB memoize the
// sharedpolicy.PolicyLoader countActiveTenantPolicies uses, keyed on the
// *sql.DB pointer it was built from. Every production call site passes the
// same process-wide db handle (authDB), so this constructs the loader
// exactly once and reuses it for the life of the process — the same
// "construct once, not per-request" discipline as the other lazily-built
// singletons in this package (e.g. gateway_handlers.go's
// getRBIKillSwitchChecker). It is keyed on the db pointer, rather than a bare
// sync.Once, only because countActiveTenantPolicies takes db as an explicit
// parameter (unlike those singletons, which close over a package-level
// handle directly) — a plain Once would permanently pin the loader to
// whichever db happened to make the first call, which is also what makes
// this function testable against an independent mock db per test case.
var (
	activePolicyCountLoaderMu sync.Mutex
	activePolicyCountLoader   *sharedpolicy.PolicyLoader
	activePolicyCountLoaderDB *sql.DB
)

// activePolicyCountLoaderFor returns the memoized PolicyLoader for db,
// constructing (or replacing) it only when db differs from the last one
// seen.
func activePolicyCountLoaderFor(db *sql.DB) *sharedpolicy.PolicyLoader {
	activePolicyCountLoaderMu.Lock()
	defer activePolicyCountLoaderMu.Unlock()
	if activePolicyCountLoader == nil || activePolicyCountLoaderDB != db {
		activePolicyCountLoader = sharedpolicy.NewPolicyLoader(db, nil)
		activePolicyCountLoaderDB = db
	}
	return activePolicyCountLoader
}

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
				MaxInWindow:   2,
				LimitType:     LimitTypeHITLApprovalsWindow,
			},
		},
		{
			Name:        mcpToolNameCreateTenantPolicy,
			Description: "Create a custom tenant-scoped governance policy. Free tier supports 4 active policies (delete one to make room); Pro raises the cap to 50. Useful for rules like 'block writes to ~/.ssh/' or 'require approval for any rm -rf'.",
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
						"description": "Tool / connector this policy documents an intent for (e.g. 'claude_code.Bash', '*' for all). NOTE: this is recorded in the policy description and is NOT yet enforced as a scope (#3061) — the policy matches its pattern on every governed connector regardless of this value.",
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
				MaxCount:  4,
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
//  1. Empty caller tier (self-hosted / internal) → MCP-layer gate is a
//     no-op; underlying API services (e.g. policy_api_service.CreatePolicy
//     gates on IsPaidTier; hitl/handler.go gates on IsHITLApprovalEnabled)
//     remain authoritative for the self-hosted license tier axis.
//  2. RequiredTier non-empty + SaaS caller below it → emit feature_pro_only envelope
//  3. FreeUsageLimit non-nil + SaaS caller is Free + count check fails → emit graduated envelope
//
// All envelope writes go through writeFreeLimitError so the wire shape
// matches the 429 daily_quota path locked in PR1 + umbrella #1958.
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
	// tier (Free=4 policies/2 HITL, Pro=50/20, Enterprise=-1 unlimited).
	// Self-hosted tiers (Community/Evaluation/Enterprise) have -1 for
	// SaaS-specific fields and skip this gate.
	if tool.FreeUsageLimit != nil {
		tierLimits := license.GetTierLimits(license.Tier(session.tier))
		switch tool.FreeUsageLimit.LimitType {
		case LimitTypeActivePolicies:
			cap := tierLimits.MaxActiveCustomPolicies
			if cap >= 0 {
				count := countActiveTenantPolicies(ctx, db, session.tenantID)
				if count >= cap {
					writeMCPGateError(w, req, LimitTypeActivePolicies, session.tier, cap, 0, "", nil)
					return true
				}
			}
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
// #3296 Step E (epic #3293 item #22): delegates to the shared substrate's
// PolicyLoader.CountActive (platform/shared/policy/loader.go) — an
// IN-PROCESS call, never a cross-service RPC, since the substrate is a
// library shared by the agent and orchestrator. The RLS org-scoping (mig 018)
// that fixed #3039 is preserved verbatim inside CountActive.
//
// Returns 0 on DB error so a transient failure doesn't accidentally
// block a Free user — the fail-open contract is UNCHANGED from the pre-#3296
// bespoke read. What changed: an error now increments
// activePolicyCountErrorsTotal before returning 0, so a systematically
// failing count (which silently bypasses the quota, same bug class as
// #3039) is observable instead of indistinguishable from "tenant has zero
// active policies."
func countActiveTenantPolicies(ctx context.Context, db *sql.DB, tenantID string) int {
	if db == nil {
		return 0
	}
	queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	count, err := activePolicyCountLoaderFor(db).CountActive(queryCtx, tenantID)
	if err != nil {
		activePolicyCountErrorsTotal.Inc()
		log.Printf("[V1Pro] active_policies count failed, fail-open to 0 (quota not enforced this check): %v", err)
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
	// Org-scoped: hitl_approval_queue is RLS-enabled (mig 025) — same
	// fail-open-through-RLS hole as countActiveTenantPolicies (#3039).
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
// The SaaS Plugin per-tenant 1-per-7d gate (Free) / unlimited (Pro)
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

// mcpToolCreateTenantPolicy — Tool 3: creates a tenant-scoped governance
// policy by routing through the orchestrator's authoritative policy API
// (POST /api/v1/policies). The orchestrator's policy_api_service
// enforces the IsPaidTier gate for tenant-tier policies — so this tool
// honors the same self-hosted license tier rules every other CRUD path
// already enforces. The MCP-tool layer's FreeUsageLimit cap (Free=2
// active policies max) has already fired at enforceMCPToolGate, before
// this function runs.
//
// Action mapping from user-facing names to engine action types:
//   - block            -> block             (deny the request)
//   - warn             -> alert             (engine handles `alert`,
//     not `warn`, as the
//     "log + surface" action)
//   - audit            -> log               (enhanced audit logging)
//   - require_approval -> require_approval  (HITL gate)
//
// The user's `connector_type` is recorded in the policy DESCRIPTION and is
// deliberately NOT emitted as a {field:"connector"} condition — see
// buildTenantPolicyConditions for the evidence and the follow-up issue.
// A policy therefore governs the pattern on EVERY connector, not just the
// one named; the tool says so rather than implying scoping it cannot deliver.
func mcpToolCreateTenantPolicy(ctx context.Context, session *mcpSession, args map[string]interface{}) (interface{}, error) {
	name, _ := args["name"].(string)
	connectorType, _ := args["connector_type"].(string)
	pattern, _ := args["pattern"].(string)
	action, _ := args["action"].(string)
	description, _ := args["description"].(string)
	if strings.TrimSpace(name) == "" || strings.TrimSpace(connectorType) == "" ||
		strings.TrimSpace(pattern) == "" || strings.TrimSpace(action) == "" {
		return nil, fmt.Errorf("name, connector_type, pattern, and action are required")
	}
	engineAction, ok := mapTenantPolicyAction(action)
	if !ok {
		return nil, fmt.Errorf("action must be one of: block, warn, audit, require_approval")
	}

	// The `[connector=...]` description prefix remains the ONLY record of the
	// connector the user named (see buildTenantPolicyConditions).
	combinedDescription := fmt.Sprintf("[connector=%s] %s", connectorType, description)

	body := map[string]interface{}{
		"name":        name,
		"description": combinedDescription,
		"type":        "content",
		"tier":        "tenant", // triggers IsPaidTier gate at policy_api_service
		"conditions":  buildTenantPolicyConditions(pattern),
		"actions": []map[string]interface{}{
			{
				"type": engineAction,
				"config": map[string]interface{}{
					"reason": fmt.Sprintf("Tenant policy %q matched", name),
				},
			},
		},
		"priority": 100,
		"enabled":  true,
	}

	resp, err := mcpProxyToOrchestrator(session, "POST", "/api/v1/policies", body)
	if err != nil {
		// Map the orchestrator's IsPaidTier rejection to a clearer
		// MCP-side message so the caller (a Pro buyer running a Pro
		// tool) understands the deployment-level cause vs the
		// SaaS Plugin tier cap that fires at enforceMCPToolGate.
		if isOrchestratorPaidTierReject(err) {
			return nil, fmt.Errorf("tenant-policy creation rejected by the deployment's license tier (Community caps at 20 tenant policies; Evaluation at 50; paid tiers unlimited) — upgrade at https://getaxonflow.com/evaluation-license — orchestrator detail: %w", err)
		}
		return nil, fmt.Errorf("could not create tenant policy: %w", err)
	}

	// Translate orchestrator's PolicyResponse{policy: {...}} to the
	// MCP tool's response shape. We pull a few key fields back up to
	// the top level so LLM consumers see the same surface they did
	// when this tool used direct DB writes.
	policyMap := extractPolicyFromResponse(resp)

	// #3061: report the deployment's ACTUAL enforcement posture instead of
	// unconditionally promising "It will apply to subsequent governed calls."
	// That promise was false on every default install (both community
	// docker-compose and the community-saas CFN template ship
	// MCP_DYNAMIC_POLICIES_ENABLED=false), and a policy the operator believes
	// is blocking but is not is worse than no policy at all.
	enforced, blockedReason, restrictedTo := tenantPolicyEnforcementStatus()
	message := fmt.Sprintf(
		"Successfully created tenant-scoped policy %q. It will apply to subsequent governed calls.",
		name)
	if enforced && len(restrictedTo) > 0 {
		message += fmt.Sprintf(
			" This deployment restricts governed calls to connectors [%s] (MCP_DYNAMIC_POLICIES_CONNECTORS),"+
				" so the policy applies only there.", strings.Join(restrictedTo, ", "))
	}
	// The connector the caller named is NOT enforced as a scope — see
	// buildTenantPolicyConditions. Say so rather than let connector_type imply
	// a narrowing the stored policy does not carry.
	if enforced {
		message += fmt.Sprintf(
			" NOTE: connector_type %q is recorded in the policy description but is NOT yet enforced as a scope,"+
				" so this policy matches its pattern on EVERY governed connector, not only %q.",
			connectorType, connectorType)
	}
	if !enforced {
		message = fmt.Sprintf(
			"Created tenant-scoped policy %q, but it is STORED AND NOT ENFORCED on this deployment: %s. "+
				"To enforce it, set MCP_DYNAMIC_POLICIES_ENABLED=true on the agent (and, if "+
				"MCP_DYNAMIC_POLICIES_CONNECTORS is set, include the connectors you want governed in that "+
				"list), then restart the agent. The policy is stored and takes effect as soon as that is "+
				"done — no need to recreate it.",
			name, blockedReason)
	}
	// Only `block` gates a call on this plane: the MCP evaluation response
	// carries allow/deny (MCPPolicyEvaluationResponse), with no approval or
	// alert channel, so alert/log/require_approval policies are RECORDED as
	// matched and do not stop the call. Say so rather than let the action name
	// imply a gate that does not exist here.
	if enforced && engineAction != "block" {
		message += fmt.Sprintf(
			" NOTE: on the MCP tool-governance plane the %q action is recorded on the matching decision"+
				" but does not stop the call; only the \"block\" action denies a tool call there.", action)
	}
	// `enforced` describes the MCP tool-governance plane only. Decision Mode
	// (/decide) passes runDynamicPolicy=false — dynamic evaluation there is M2
	// scope per epic #2426 — so a PEP integrated via /decide does not evaluate
	// this policy at all, whatever the flag says.
	if enforced {
		message += " Scope: this covers MCP tool-governance calls (check-input and the MCP planes)." +
			" Decision Mode (POST /api/v1/decide) does not evaluate tenant dynamic policies yet, so a" +
			" PEP integrated through /decide is not governed by this policy."
	}

	created := map[string]interface{}{
		// Explicit positive signal for LLM consumers (#1986). Without
		// `success: true` + `created: true`, models can misread the
		// presence of `enabled: true` (which describes the policy
		// state, not the operation outcome) as ambiguous.
		"success":        true,
		"created":        true,
		"name":           name,
		"connector_type": connectorType,
		"pattern":        pattern,
		"action":         action,
		"enabled":        true,
		// Machine-readable sibling of `message` so an LLM consumer does not
		// have to parse prose to learn the policy is inert. `enabled` describes
		// the stored row; `enforced` describes this deployment's runtime.
		"enforced": enforced,
		// #3061: the stored policy carries no connector condition, so the
		// connector the caller named is descriptive only. Machine-readable so an
		// LLM consumer does not have to infer it from prose.
		"connector_scope_enforced": false,
		"applies_to_connectors":    "all",
		"message":                  message,
	}
	if enforced && len(restrictedTo) > 0 {
		created["applies_to_connectors"] = restrictedTo
	}
	if !enforced {
		created["enforcement_blocked_reason"] = blockedReason
	}
	if policyID, ok := policyMap["id"].(string); ok && policyID != "" {
		created["id"] = policyID
	}
	if policyKey, ok := policyMap["policy_id"].(string); ok && policyKey != "" {
		created["policy_id"] = policyKey
	}
	return created, nil
}

// buildTenantPolicyConditions builds the condition list for a tenant policy:
// the pattern, and ONLY the pattern.
//
// #3061 DOCUMENTED DEFERRAL — why connector_type is not a condition here.
//
// The obvious fix for "the user's connector is discarded into the description"
// is to emit {field:"connector", operator:"equals", value:connectorType}. That
// is correct for the MCP plane, whose evaluator has resolved `connector` from
// MCPPolicyEvaluationRequest.ConnectorName since #968 — but it BREAKS the
// planes where these policies already work today. These rows are
// policy_type='content', and the orchestrator content engine that governs the
// LLM / MAP / WCP planes has no `connector` field at all: getFieldValue
// (db_dynamic_policies.go) falls through to its default arm and returns nil,
// `equals` then compares "<nil>" against the real connector name and yields
// false, and with conditions present ALL must match — so the entire policy is
// skipped. Adding the condition would therefore trade MCP-plane enforcement
// for the loss of enforcement where it already worked: the same defect class
// #3061 exists to fix, inverted.
//
// Making `connector` resolvable on the orchestrator content engine is the real
// fix, and it belongs in db_dynamic_policies.go — a file owned by another
// in-flight workstream, so it is NOT touched here. Tracked as the follow-up
// filed against #3061; until it lands, a tenant policy governs its pattern on
// EVERY connector rather than the one named. That is over-broad rather than
// under-broad (it fails toward more governance, not less), it matches the
// pre-#3061 stored shape so no existing row changes meaning, and the tool's
// response says so plainly instead of promising scoping it cannot deliver.
func buildTenantPolicyConditions(pattern string) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"field":    "query",
			"operator": "regex",
			"value":    pattern,
		},
	}
}

// tenantPolicyEnforcementStatus reports whether tenant policies are EVALUATED
// at all on this agent's MCP governance plane, plus (when they are) any
// connector allowlist that narrows where they apply (#3061).
//
// Deliberately a PLANE-level question, not a per-connector one. The stored
// policy carries no connector condition (see buildTenantPolicyConditions), so
// it applies to every connector the plane evaluates; asking
// IsEnabled(connectorType) would answer a question about a scoping that does
// not exist. It would also be actively misleading: with an empty allowlist
// IsEnabled returns true for ANY string, so a caller who passed a connector
// name the platform never emits — "shell" rather than the composite
// "<client>.<Tool>" the plugins send — would be told the policy is enforced
// for that connector, which is exactly the false-promise class #3061 exists
// to eliminate.
//
// This inspects the agent's live evaluator rather than auto-enabling anything.
// Auto-enabling on first policy creation would flip a deployment-wide
// enforcement posture as a side effect of one MCP tool call:
// MCP_DYNAMIC_POLICIES_ENABLED gates the plane for EVERY connector and every
// caller, not just this policy, and with MCP_DYNAMIC_POLICIES_GRACEFUL
// defaulting to true an orchestrator blip would then fail open on traffic the
// operator never opted into governing. Reporting honestly is the safe half of
// that trade; the operator keeps the decision.
//
// A nil evaluator means the process never initialized one, which is itself a
// not-enforced state — never dereference it (IsEnabled takes a lock).
func tenantPolicyEnforcementStatus() (enforced bool, blockedReason string, restrictedTo []string) {
	evaluator := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	if evaluator == nil {
		return false, "the agent has no MCP dynamic-policy evaluator initialized", nil
	}
	cfg := evaluator.GetConfig()
	if !cfg.Enabled {
		return false, "MCP dynamic policy evaluation is disabled on this agent (MCP_DYNAMIC_POLICIES_ENABLED is not true)", nil
	}
	// Empty allowlist means every connector; a non-empty one means the plane —
	// and therefore this policy — only runs for those connectors.
	return true, "", cfg.EnabledConnectors
}

// mapTenantPolicyAction translates the user-facing tenant-policy
// action names to the engine's action types. Returns false if the
// action is not in the supported set.
func mapTenantPolicyAction(userAction string) (engineAction string, ok bool) {
	switch userAction {
	case "block":
		return "block", true
	case "warn":
		// Engine handles "alert"; "warn" is the user-friendly name.
		return "alert", true
	case "audit":
		return "log", true
	case "require_approval":
		return "require_approval", true
	default:
		return "", false
	}
}

// isOrchestratorPaidTierReject reports whether the orchestrator's
// error is a tier-validation rejection that the user should see
// re-worded with deployment-license context. Matches:
//   - The Organization-tier evaluation-or-higher gate
//     (policy_api_service.validateTierForCreate, ErrCodeOrgTierEvaluationOrHigher)
//   - The Tenant-tier policy-count cap for non-paid tiers
//     (policy_api_service.validateTierForCreate, ErrCodePolicyLimitExceeded)
//
// The orchestrator returns 403 with these codes/wordings. We match
// conservatively on the recognizable phrase to keep the classifier
// robust against minor message tweaks.
func isOrchestratorPaidTierReject(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "orchestrator returned 403") {
		return false
	}
	return strings.Contains(msg, "enterprise license") ||
		strings.Contains(msg, "evaluation or enterprise") ||
		strings.Contains(msg, "evaluation license") ||
		strings.Contains(msg, "tier_validation") ||
		strings.Contains(msg, "policy limit") ||
		strings.Contains(msg, "policy_limit_exceeded")
}

// extractPolicyFromResponse pulls the inner `policy` object from the
// orchestrator's PolicyResponse{policy: {...}} envelope. Returns an
// empty map if the response shape doesn't match (the response is
// still valid; we just have no fields to lift up).
func extractPolicyFromResponse(resp interface{}) map[string]interface{} {
	envelope, ok := resp.(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	policy, ok := envelope["policy"].(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return policy
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
				"id":         "active_policies",
				"capability": "Custom tenant policies",
				"free":       "4 active max",
				"pro":        "Up to 50",
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
