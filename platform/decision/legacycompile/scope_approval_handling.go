// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import "sort"

// WHAT EACH ENFORCING SCOPE DOES WITH AN APPROVAL CHALLENGE (#4249 rows
// 5768885106, 5774872368).
//
// An anchored decision can answer a request with a challenge: an approval
// requirement matched it. Whether the scope that decided it can HOLD that
// challenge as a pending approval, or refuses the request instead, is a fact
// about the seam, and three readers need it: the publish validator's warnings
// on an approval requirement bound where nothing holds
// (authoring.noHoldApprovalScopes), the activation census of which pack
// step-ups sit on a holding scope, and the census of every file that handles a
// challenge (activation's TestEveryChallengeHandlingSiteIsCensused), which holds
// this declaration to the seams.
//
// This is that fact, stated once, beside scopeActions and keyed on exactly its
// scopes (TestEveryEnforcingScopeSaysWhatAChallengeBecomes): a new scope must
// say what a challenge becomes there before anything can bind on it.
type ApprovalHandling int

const (
	// ApprovalRefused: the seam refuses the request with the reason
	// approval_required; nothing is held.
	ApprovalRefused ApprovalHandling = iota + 1
	// ApprovalWithheld: the seam turns the challenge into a require_approval
	// result that the multi-agent step gate withholds as
	// approval_requires_durable_record (#4382): the step never runs and nothing
	// is held. Confirm and step mode hold a step through a gate override that
	// asks no policy, and their one policy decision, when the released step
	// runs, refuses a challenge approval_required: no mode holds a multi-agent
	// step's approval.
	ApprovalWithheld
	// ApprovalHeldOnEnterprise: the Enterprise build holds the challenge as a
	// pending approval a retry spends once (agent/approval_hold_enterprise.go,
	// #4375); the Community build refuses it approval_required
	// (agent/approval_hold_community.go).
	ApprovalHeldOnEnterprise
	// ApprovalHeld: the seam holds the challenge in every build (the workflow
	// control plane's step gate, orchestrator/wcp_enforcing_seam.go).
	ApprovalHeld
)

// Holds reports whether a challenge can be held on the scope in some build.
func (h ApprovalHandling) Holds() bool {
	return h == ApprovalHeld || h == ApprovalHeldOnEnterprise
}

func (h ApprovalHandling) String() string {
	switch h {
	case ApprovalRefused:
		return "refused"
	case ApprovalWithheld:
		return "withheld"
	case ApprovalHeldOnEnterprise:
		return "held-on-enterprise"
	case ApprovalHeld:
		return "held"
	}
	return "unknown"
}

var scopeApprovalHandling = map[string]ApprovalHandling{
	"decide":                ApprovalHeldOnEnterprise,
	"gateway_request":       ApprovalRefused,
	"mcp:request":           ApprovalHeldOnEnterprise,
	"mcp:response":          ApprovalRefused,
	"proxy_request":         ApprovalRefused,
	"openai_compatible":     ApprovalRefused,
	"wcp":                   ApprovalHeld,
	"orchestrator_request":  ApprovalRefused,
	"map":                   ApprovalWithheld,
	"orchestrator_response": ApprovalRefused,
	"cowork_ingest":         ApprovalRefused,
}

// ApprovalHandlingOf returns what scope does with an approval challenge, or 0
// for a scope no enforcing seam decides on.
func ApprovalHandlingOf(scope EnforcementScope) ApprovalHandling {
	return scopeApprovalHandling[scope.String()]
}

// HoldingScopes returns the enforcing scopes that hold a challenge in some
// build, sorted by their canonical names.
func HoldingScopes() []EnforcementScope {
	var out []EnforcementScope
	for _, s := range AllScopes() {
		if ApprovalHandlingOf(s).Holds() {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
