// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"sort"
)

// WHICH ACTIONS EACH ENFORCING SCOPE PRESENTS (#4371).
//
// An organization's control may declare the scopes it binds on (`binds_on`,
// pdp.Policy.BindsOn). The publish validator refuses a scope that presents none
// of the actions the control selects, because such a scope would never be
// reached by it and a typo there silently means "nowhere". That needs one
// statement of what each scope presents, and until #4371 the tree had none:
// the deployment vocabulary's actions carry no plane, and
// registry/legacy_plane_peps.tsv carries capabilities only.
//
// This is that statement, and it is the ONLY one. The deployment vocabulary
// (authoringcatalog) reads it to state, per action, the scopes a document may
// name. It is held to the seams that present each action by value, in both
// directions: platform/agent's TestEverySeamPresentsWhatScopeActionsStates over
// its enforcingSeams, and platform/orchestrator's twin over
// orchestratorEnforcingScopes. A scope listed here with no seam, or a seam whose
// scope is not listed, fails one of them.
//
// The action names are the deployment vocabulary's (authoringcatalog's
// ActionLLMCompletion, ActionToolCall, ActionAgentInvoke), restated because
// authoringcatalog imports this package; authoringcatalog's
// TestScopeActionsNameOnlyDeploymentActions welds them.
var scopeActions = map[string][]string{
	// The Decision API: the caller's stage names the action (llm, tool, agent).
	"decide": {"agent.invoke", "llm.completion", "tool.call"},
	// The gateway pre-check: the stage decisionStageForPreCheck derives.
	"gateway_request": {"llm.completion", "tool.call"},
	// MCP: a tool call on the request pass (tools/call, check_policy) and the
	// tool's response on the response pass.
	"mcp:request":  {"tool.call"},
	"mcp:response": {"tool.call"},
	// /api/request and the OpenAI-compatible route forward a completion.
	"proxy_request":     {"llm.completion"},
	"openai_compatible": {"llm.completion"},
	// The workflow control plane's step gate: llm_call as llm.completion,
	// tool_call and connector_call as tool.call, human_task as agent.invoke.
	"wcp": {"agent.invoke", "llm.completion", "tool.call"},
	// The orchestrator's request plane: /api/v1/process as llm.completion and
	// /api/v1/plan/execute as agent.invoke (route_request_enforcing_seam.go).
	// Neither route can hold an approval, so a challenge there is refused
	// approval_required (authoring.CodeBindsOnOrchestratorRequestNoHold warns
	// of it at publish). Until #4249 row 5706695827 the two routes decided
	// under wcp's scope beside the step gate.
	"orchestrator_request": {"agent.invoke", "llm.completion"},
	// The multi-agent plane, as the MAP HITL adapter decides each step:
	// llm-call as llm.completion, connector/function/api-call as tool.call. A
	// plan run in confirm or step mode is gated through the workflow control
	// plane's step gate with a gate override, which asks no policy.
	"map": {"llm.completion", "tool.call"},
	// The orchestrator's response plane: the completion /api/v1/process returns.
	"orchestrator_response": {"llm.completion"},
	// The cowork ingest storage pass (Enterprise only; #4259): a user prompt
	// and an assistant response as llm.completion, a tool result as tool.call.
	"cowork_ingest": {"llm.completion", "tool.call"},
}

// EnforcingScopes returns every scope an enforcing seam decides on, in either
// binary, as canonical scope strings, sorted.
func EnforcingScopes() []string {
	out := make([]string, 0, len(scopeActions))
	for s := range scopeActions {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ScopeActions returns the actions scope presents, sorted, as a copy; nil for a
// scope no enforcing seam decides on.
func ScopeActions(scope EnforcementScope) []string {
	return append([]string(nil), scopeActions[scope.String()]...)
}

// ScopesPresenting returns the canonical names of the enforcing scopes that
// present action, sorted.
func ScopesPresenting(action string) []string {
	var out []string
	for scope, actions := range scopeActions {
		for _, a := range actions {
			if a == action {
				out = append(out, scope)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// RouteSeamSplitCatalogVersion is the deployment catalog version at which the
// orchestrator's two request routes stopped deciding under the step gate's
// `wcp` scope and became `orchestrator_request` (#4249 row 5706695827).
//
// A DOCUMENTED LITERAL, not a reference to DeploymentCatalogVersion, because it
// names ONE release's vocabulary for ever: a later unrelated bump must not move
// what a document published before the split binds. authoringcatalog's
// TestTheRouteSeamSplitVersionIsThisCatalogsOrOlder holds it to that literal and
// requires DeploymentCatalogVersion to be at least it.
const RouteSeamSplitCatalogVersion int64 = 7

// BindsOnPinned is BindsOn for a control of a document published under catalog
// version pin (0 = an artifact whose provenance carries none, which is every
// artifact published before the pin existed).
//
// THE ONE COMPATIBILITY RULE OF THE ROUTE-SEAM SPLIT. Until
// RouteSeamSplitCatalogVersion, `wcp` meant the workflow step gate AND the two
// request routes, so a document that named it governed both. Splitting the
// plane must not narrow what an organization already published: a control of
// such a document that binds on `wcp` therefore also binds on
// `orchestrator_request`, until the document is republished against a catalog
// that states the two separately. A document published at or after the split
// binds exactly what it names.
//
// It is the ONE function both the omission and its backstop read
// (activation/binds_on.go), so the two cannot disagree about a control.
func BindsOnPinned(binds *[]string, pin int64, scope EnforcementScope) bool {
	if BindsOn(binds, scope) {
		return true
	}
	if pin >= RouteSeamSplitCatalogVersion || binds == nil {
		return false
	}
	if scope.Plane != PlaneOrchestratorRequest || scope.Phase != "" {
		return false
	}
	return BindsOn(binds, MustScopeFor(PlaneWCP, ""))
}

// BindsOn reports whether a control declaring binds binds on scope. Absent
// (nil) binds on every scope: that is the meaning every document published
// before #4371 has, and it must not move. A non-nil empty list is refused at
// publication (authoring.CodeBindsOnEmpty) and at activation before this is
// asked, because neither answer would be safe for every control: "nowhere"
// removes a constraint from every scope, and "everywhere" would let `[]` mean
// what its author did not write. It is answered false here only so that no
// caller can read it as "everywhere".
func BindsOn(binds *[]string, scope EnforcementScope) bool {
	if binds == nil {
		return true
	}
	want := scope.String()
	for _, s := range *binds {
		if s == want {
			return true
		}
	}
	return false
}
