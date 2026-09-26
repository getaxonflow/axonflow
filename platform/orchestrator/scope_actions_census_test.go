// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/legacycompile"
)

// TestEverySeamPresentsWhatScopeActionsStates is the orchestrator's half of
// the agent's twin (#4371): legacycompile's statement of which actions each
// scope presents, held to this binary's seams by value.
//
// Each set is read from the table the seam itself reads: the step gate's
// wcpStepActions on wcp, the route seam's two route actions on
// orchestrator_request (its own plane since #4249 row 5706695827), the MAP
// adapter's mapStepActions on map, and the response seam's one action.
func TestEverySeamPresentsWhatScopeActionsStates(t *testing.T) {
	set := func(actions ...string) []string {
		m := map[string]bool{}
		for _, a := range actions {
			m[a] = true
		}
		out := make([]string, 0, len(m))
		for a := range m {
			out = append(out, a)
		}
		sort.Strings(out)
		return out
	}
	var step, mapped []string
	for _, a := range wcpStepActions {
		step = append(step, a)
	}
	for _, a := range mapStepActions {
		mapped = append(mapped, a)
	}
	route := set(processRouteAction, planExecuteRouteAction)
	presents := map[string][]string{
		wcpSeamScope.String():                 set(step...),
		orchestratorRequestSeamScope.String(): route,
		mapSeamScope.String():                 set(mapped...),
		orchestratorResponseScope.String():    set(authoringcatalog.ActionLLMCompletion),
	}
	if len(presents) != len(orchestratorEnforcingScopes) {
		t.Fatalf("this census states %d scopes and the orchestrator registers %d (%v): a seam was added or removed; state what it presents",
			len(presents), len(orchestratorEnforcingScopes), orchestratorEnforcingScopeNames())
	}
	for _, scope := range orchestratorEnforcingScopes {
		got, ok := presents[scope.String()]
		if !ok {
			t.Errorf("the orchestrator registers %s and this census does not state what it presents", scope)
			continue
		}
		if want := legacycompile.ScopeActions(scope); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s presents %v and legacycompile's scopeActions states %v", scope, got, want)
		}
	}
}

// TestTheOrchestratorSeamsHandleAChallengeAsTheDeclarationSays welds
// legacycompile's declaration of what each scope does with an approval challenge
// (scopeApprovalHandling, #4249 row 5768885106) to this binary's seams, in the
// same census that holds what they present. The multi-agent seam withholds a
// challenge as mapApprovalRequiresDurableRecord (map_step_gate.go; the
// behaviour is TestWorkflowExecuteWithholdsAStepATypedApprovalHoldsWhateverTheFlagSays
// in map_step_gate_4382_test.go), so the
// declaration must say Withheld there; the step gate holds (wcp_enforcing_seam.go),
// and the two request routes and the response seam refuse approval_required.
func TestTheOrchestratorSeamsHandleAChallengeAsTheDeclarationSays(t *testing.T) {
	if mapApprovalRequiresDurableRecord != "approval_requires_durable_record" {
		t.Fatalf("the multi-agent seam's withheld code is %q; the declaration's Withheld names approval_requires_durable_record", mapApprovalRequiresDurableRecord)
	}
	for scope, want := range map[legacycompile.EnforcementScope]legacycompile.ApprovalHandling{
		mapSeamScope:                 legacycompile.ApprovalWithheld,
		wcpSeamScope:                 legacycompile.ApprovalHeld,
		orchestratorRequestSeamScope: legacycompile.ApprovalRefused,
		orchestratorResponseScope:    legacycompile.ApprovalRefused,
	} {
		if got := legacycompile.ApprovalHandlingOf(scope); got != want {
			t.Errorf("legacycompile declares %s %s; this binary's seam there is %s", scope, got, want)
		}
	}
}
