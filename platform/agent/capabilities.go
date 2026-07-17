// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// PlatformCapability describes a feature supported by the platform.
type PlatformCapability struct {
	Name        string `json:"name"`
	Since       string `json:"since"`
	Description string `json:"description"`
}

// SDKCompatInfo describes SDK version compatibility for this platform version.
type SDKCompatInfo struct {
	MinSDKVersion         map[string]string `json:"min_sdk_version"`
	RecommendedSDKVersion map[string]string `json:"recommended_sdk_version"`
}

// PluginCompatInfo describes plugin version compatibility for this platform
// version. Mirrors SDKCompatInfo so plugins can run the same min/recommended
// gate against /health that SDKs do — see Python SDK's
// `health_check_detailed()` and Go SDK's `SDKCompatibility.MinSDKVersionFor()`
// for the reference consumer pattern.
//
// Keys are the canonical plugin IDs the agent tracks in
// `integration_activation.go::knownIntegrations`. Keep this list in lockstep
// with that registry — a regression test (TestPluginCompatibilityKeysMatchKnownIntegrations)
// fails if the two drift apart.
//
//   - openclaw       — npm @axonflow/openclaw (TypeScript plugin)
//   - claude-code    — Claude Code CLI plugin (axonflow-claude-plugin)
//   - cursor         — Cursor CLI plugin (axonflow-cursor-plugin)
//   - codex          — OpenAI Codex CLI plugin (axonflow-codex-plugin)
//   - claude-desktop — Claude Desktop MCP governance proxy
//     (axonflow-claude-desktop-plugin; identifies on the wire as
//     "mcp-proxy/<v>" via X-Axonflow-Client)
//
// `MinPluginVersion[id]` is the lowest version that speaks the current
// platform's wire / hook contract. A plugin running below the floor logs
// an actionable upgrade warning. `RecommendedPluginVersion[id]` is the
// version this platform was tested against; below recommended-but-above-min
// is informational only.
type PluginCompatInfo struct {
	MinPluginVersion         map[string]string `json:"min_plugin_version"`
	RecommendedPluginVersion map[string]string `json:"recommended_plugin_version"`
}

func getCapabilities() []PlatformCapability {
	return []PlatformCapability{
		{Name: "health_check", Since: "1.0.0", Description: "Basic health endpoint"},
		{Name: "proxy_llm_call", Since: "1.0.0", Description: "Proxy mode LLM calls with policy enforcement"},
		{Name: "audit_llm_call", Since: "1.0.0", Description: "Audit logging for LLM calls"},
		{Name: "static_policies", Since: "2.0.0", Description: "System policy CRUD"},
		{Name: "gateway_mode", Since: "3.0.0", Description: "Gateway mode integration"},
		{Name: "dynamic_policies", Since: "3.2.0", Description: "Runtime dynamic policy engine"},
		{Name: "multi_agent_planning", Since: "4.3.0", Description: "MAP plan and execute lifecycle"},
		{Name: "workflow_control", Since: "4.3.0", Description: "WCP workflow lifecycle management"},
		{Name: "execution_replay", Since: "4.3.0", Description: "Execution recording and replay"},
		{Name: "cost_controls", Since: "4.4.0", Description: "Budget and cost management"},
		{Name: "media_governance", Since: "4.4.0", Description: "Multimodal image governance"},
		{Name: "wcp_step_metrics", Since: "4.5.0", Description: "WCP step-complete post-execution metrics"},
		{Name: "mcp_check_endpoints", Since: "4.7.0", Description: "Standalone MCP policy check-input/check-output"},
		{Name: "circuit_breaker", Since: "4.7.0", Description: "Circuit breaker pipeline enforcement"},
		{Name: "version_discovery", Since: "4.8.0", Description: "Version and capability discovery"},
		{Name: "hitl_response_parity", Since: "7.4.0", Description: "WCP + MAP approve/reject responses share retry_context, approver metadata, policies_matched (ADR-046)"},
		{Name: "plugin_compatibility", Since: "7.5.0", Description: "Health response advertises min_plugin_version + recommended_plugin_version per plugin id (mirrors sdk_compatibility)"},
		{Name: "community_saas_recovery", Since: "7.7.0", Description: "POST /api/v1/recover[/verify] free-tier credential recovery via emailed magic link (Community SaaS only)"},
		{Name: "plugin_claim_license", Since: "7.7.0", Description: "Stripe-driven Pro v1 plugin license issuance (POST /api/v1/billing/stripe-webhook) + per-request X-License-Token validation (Community SaaS only)"},
		{Name: "v1_pro_upgrade_envelope", Since: "7.8.0", Description: "Structured V1 upgrade envelope on every Free-tier limit hit (429 daily_quota + 403 active_policies / hitl_approvals_window / feature_pro_only) with locked compare_url + buy_url + Retry-After header (Community SaaS only)"},
		{Name: "v1_pro_mcp_tools", Since: "7.8.0", Description: "Five new MCP tools on /api/v1/mcp-server (axonflow_get_tenant_id, axonflow_request_approval, axonflow_create_tenant_policy, axonflow_get_cost_estimate, axonflow_list_pro_features) with tier-aware tools/list filtering and graduated FreeUsageLimit gates"},
		{Name: "v1_pro_graduated_freemium", Since: "7.8.0", Description: "Free tier exposes a taste of Pro capabilities — 2 active custom tenant policies + 1 HITL approval per rolling 7d — with structured 403 envelope on cap-hit; Pro tier removes both caps (Community SaaS only)"},
		{Name: "decision_obligations", Since: "8.6.0", Description: "Decision Mode /api/v1/decide emits self-describing, engine-fulfillable redact_pii obligations carrying a fulfillment block (endpoint, method, phase, content_types) so a PEP discharges them via the engine instead of hand-rolling redaction (ADR-056/057)"},
		{Name: "two_touch_redaction", Since: "8.6.0", Description: "Request-phase (POST /api/v1/mcp/check-input → redacted_statement + redaction_evaluated) and response-phase (POST /api/v1/mcp/check-output → redacted_data) PII redaction both return engine-masked content, so PEPs never hand-roll redaction on either leg"},
		{Name: "client_version_telemetry", Since: "9.7.0", Description: "Per-client version-distribution telemetry: validated X-Axonflow-Client client id + version pairs are recorded into the axonflow_client_version_requests_total counter on the decide and MCP check-output planes (Enterprise builds; Community builds no-op and register no series). Telemetry-only — never consulted for auth or a verdict"},
		{Name: "seam_capability_decisioning", Since: "9.11.0", Description: "Seam-capability-aware obligations: a PEP advertises what its seam can discharge via DecideRequest.fulfillment_capabilities (vocabulary: request_body_redaction, request_header_mutation) and POST /api/v1/decide emits only obligations that caller can fulfill. A request-body redaction suppressed on a non-capable seam (e.g. Envoy ext_authz, which is headers-only) applies the org's obligation-fallback posture — log (default: allow, no obligation, canonical audit row records the suppressed redaction + detected categories) or block (deny) — configurable per org on the obligation_fallback detection-posture category. The posture is resolved server-side from the org, never from the request; absent/empty capabilities means a legacy caller and reproduces pre-9.11.0 behavior exactly (all SDKs unaffected). Replaces the adapter-local allow→403 conversion so every outcome is an engine round-trip (ADR-056)"},
		{Name: "identity_header_attribution", Since: "9.9.0", Description: "Trust-gated per-user audit attribution: X-User-Email / X-Session-Id (and X-User-ID on the MCP-server plane) attribute audit_logs rows on all four governance planes (decide, MCP check-input, MCP check-output, MCP-server tools/call) when the deployment opts in via AXONFLOW_TRUST_IDENTITY_HEADERS=true (default off — untrusted headers are ignored and a detection warning is logged). Attribution-only — a forged header can never influence a verdict, authz decision, or tenant/org resolution; per-user features (ADR-044 session overrides, user-scoped dynamic policies) key on the trusted identity only under the gate"},
	}
}

func getSDKCompatibility() SDKCompatInfo {
	return SDKCompatInfo{
		// Floor of the current major line. The SDK major bumped from
		// v7 to v8 during the v7.9.0 release-train (#2016 pre-emptive
		// floor bump 2026-05-08, folded into the v7.9.0 community sync
		// at #2102 on 2026-05-09). The current v8.0.0 platform bump
		// (#2308) did NOT change the SDK floor — it stayed at v8.0.0.
		// Callers below 8.0.0 lack the typed 429 RateLimitError
		// upgrade-envelope handling and the list_decisions method
		// (Session γ / #1982). Advertising the floor signals to them
		// that they should upgrade to keep envelope-aware error
		// handling and the new list endpoint. Note: Go's major bump
		// also changes the import path (axonflow-sdk-go/v7 → /v8) per
		// Go modules v2+ rules.
		// rust joined the compat maps in the 9.7.0 release-train. Its 0.x
		// preview line is versioned independently of the 8.x SDKs; the
		// floor is 0.7.0 — the first rust release that speaks the current
		// Decision Mode PEP contract (decide → fulfill → forward, engine-
		// only fulfill, fail-closed on missing verdict; epic #2563). The
		// 0.5/0.6 previews predate that contract.
		MinSDKVersion: map[string]string{
			"python":     "8.0.0",
			"typescript": "8.0.0",
			"go":         "8.0.0",
			"java":       "8.0.0",
			"rust":       "0.7.0",
		},
		// Latest tag this platform was tested against. Kept in lockstep
		// with each SDK's release-train tag. java bumped 8.5.0 -> 8.5.1 in
		// the 9.1.1 security patch (2026-06-16): 8.5.1 adds a production
		// guard around the opt-in insecure-TLS dev hatch plus dependency
		// CVE clears. python/typescript/go bumped 8.5.0 -> 8.5.1 in the
		// 9.7.0 release-train (epic #2861 SDK hostile sweep): go 8.5.1
		// fails closed on 4xx auth errors instead of silently allowing,
		// python 8.5.1 bridges sync interceptors onto a persistent event
		// loop + detects AsyncOpenAI clients, typescript 8.5.1 sends auth
		// on getPlanStatus. java stays 8.5.1 (no new java tag this train).
		// rust enters at 0.8.1 (execute_plan status fix + the 9.7.0 train
		// examples baseline).
		RecommendedSDKVersion: map[string]string{
			"python":     "9.0.0",
			"typescript": "9.0.0",
			"go":         "9.0.0",
			"java":       "9.0.0",
			"rust":       "0.8.1",
		},
	}
}

// getPluginCompatibility reports the min and recommended plugin versions for
// every plugin the platform speaks to. The values track the floor of each
// plugin's current major line and its latest released tag — kept in lockstep
// with each plugin's release-notes header. A future PR that ships the next
// plugin major (claude/cursor/codex graduating to 1.0; openclaw to 2.0)
// updates these values as part of the same release-train commit so the
// downgrade-warning gate flips on the moment the new majors are tagged.
func getPluginCompatibility() PluginCompatInfo {
	return PluginCompatInfo{
		// Floor of each plugin's current released contract. Bumped from
		// {2.0.0, 1.0.0×3} to {2.4.0, 1.4.0×3} during the v7.9.0
		// release-train prep (#2102): openclaw 2.0–2.3.x carried bugs
		// we no longer support; claude-code/cursor/codex 1.0–1.3.x
		// predate the v8 list_decisions integration. Anything below
		// this floor speaks an out-of-contract version and receives
		// the actionable downgrade-warning header on every governed
		// call. The plugin tags shipped within ~15-30 minutes of the
		// v7.9.0 community sync per the release-train order locked at
		// #2047.
		// claude-desktop joined the registry in the 9.7.0 release-train.
		// Its floor is 0.2.0 — the first release whose response redaction
		// goes through the authoritative engine check-output endpoint and
		// whose response plane is unconditionally fail-closed; the 0.1.x
		// proxies hand-rolled a divergent local-regex redaction we no
		// longer support.
		MinPluginVersion: map[string]string{
			"openclaw":       "2.4.0",
			"claude-code":    "1.4.0",
			"cursor":         "1.4.0",
			"codex":          "1.4.0",
			"claude-desktop": "0.2.0",
		},
		// Latest tag this platform was tested against. Kept in lockstep
		// with each plugin's release-train tag. Bumped to claude/cursor/codex
		// 1.4.0 + openclaw 2.4.0 during the v7.9.0 release-train (#2102
		// on 2026-05-09) — the new minor carries the SDK v8 list_decisions
		// integration so the "show me the last decisions for this user"
		// affordance lands natively in each host. The v8.0.0 platform bump
		// (#2308) did NOT change the plugin recommended-version. Bumped
		// claude-code + cursor to 1.5.3 during the v8.5.2 release-train —
		// 1.5.3 ships the headersHelper ${CLAUDE_PLUGIN_ROOT} fix so the
		// plugins send Basic auth correctly against self-hosted/Enterprise.
		// claude-code bumped 1.5.3 -> 1.6.0 (2026-06-10) — 1.6.0 adds the
		// endpoint-gated Community-SaaS credential + the self-hosted-auth.json
		// Enterprise credential fallback so MCP tool execution no longer 401s
		// on self-hosted/Enterprise agents (axonflow-claude-plugin#94/#95);
		// cursor stays 1.5.3 (no 1.6.0 cut). codex stays 1.5.2 (its v8.5.2 fix
		// was documentation-only; no codex 1.5.3 was cut); openclaw bumped
		// 2.6.1 -> 2.6.5 to track its latest published release (the prior value
		// lagged the registry). openclaw bumped 2.6.5 -> 2.6.6 in the 9.1.1
		// security patch (2026-06-16): 2.6.6 clears a runtime protobufjs CVE
		// and is republished on ClawHub/npm. claude-code/cursor/codex are
		// unchanged for 9.1.1. claude-code bumped 1.6.0 -> 1.7.0 in the
		// 9.2.2 release-train. claude-code bumped 1.7.0 -> 1.8.0 in the
		// 9.3.0 release-train (ships with the v9.3.0 platform minor carrying
		// the audit-visibility bundle; the 1.8.0 marketplace release fires
		// immediately after the tag). claude-code bumped 1.8.0 -> 1.9.0 for
		// the v1.9.0 identity-hardening release (attribution-forgery notice +
		// control-byte sanitizer, #102/#103), then 1.9.0 -> 1.9.1 in the
		// 9.7.0 release-train (correct on-wire version reporting on the hook
		// + MCP planes + a plugin.json alignment gate, plugin#105; released
		// 2026-07-09). claude-desktop enters at 0.3.1 in the 9.7.0 train —
		// 0.3.1 sends X-Axonflow-Client: mcp-proxy/<v> on decide +
		// check-output so the per-client version telemetry can see the
		// proxy fleet (desktop#23; the tag ships with this train).
		// cursor stays 1.5.3, codex
		// stays 1.5.2, openclaw stays 2.6.6.
		// 9.10.0 release-train (#2919 fleet RBAC per-user identity): all four
		// bumped — claude-code 1.9.1 -> 1.10.0, cursor 1.5.3 -> 1.6.0, codex
		// 1.5.2 -> 1.6.0, openclaw 2.6.6 -> 2.7.0 — each now sends the per-user
		// token header on every governed surface so fleet developers
		// get per-user read-scoping; a plugin below the recommended version
		// keeps working (floor unchanged) but reads the shared-identity
		// zero-rows fallback until upgraded. claude-desktop unchanged.
		// The other
		// plugin tags are live on their registries (openclaw 2.6.6 on
		// npm/ClawHub, cursor 1.5.3 + codex 1.5.2; claude-code/cursor on the
		// GitHub marketplace, codex on ClawHub). Plugins below the recommended
		// version receive an actionable upgrade-warning header on every
		// governed call; the MinPluginVersion floor stays 1.4.0 / 2.4.0
		// (claude-desktop's floor is 0.2.0, see above).
		RecommendedPluginVersion: map[string]string{
			"openclaw":       "2.8.0",
			"claude-code":    "1.11.0",
			"cursor":         "1.7.0",
			"codex":          "1.7.0",
			"claude-desktop": "0.3.1",
		},
	}
}
