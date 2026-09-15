// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package retiredenv refuses to boot a process whose environment still sets a
// variable v11 retired (PRD v11 §5.1).
//
// # WHY A REFUSAL AND NOT A WARNING
//
// The retired variables SELECTED what decided a request: which engine authored
// a verdict, whether the old and new engines were compared, whether a
// credential was admitted by the identity plane or by the resolution it
// replaced, whether an organization's tenant dynamic policies decided the MCP
// plane, whether an ML scorer weighed a FinCrime request, and how long an
// approved step-up stayed spendable as a grant. v11 has one author, one
// identity model, no comparison, no MCP dynamic-policy plane, no FinCrime
// scorer and no approval grant, so none of them can do anything - and an operator who set
// one had a reason and believes it still does it. A variable ignored with a log
// line is the fail-open shape: the deployment runs in a posture its own
// configuration misdescribes. A container that will not start is the one
// failure an operator notices immediately, and the message says what to remove
// and why.
//
// An EMPTY value is not refused. The compose files and CloudFormation
// templates of every release before v11 pass these through empty
// (`AXONFLOW_DECISION_SHADOW_MODE: ${AXONFLOW_DECISION_SHADOW_MODE:-}`), and an
// empty variable chose nothing before v11 either.
package retiredenv

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// PRD is the document every refusal names (PRD v11 §5.1).
const PRD = "technical-docs/product/PRD_V11_POLICY_DECISION_PLANE.md"

// OperatorNotes is the page a refusal of the decision mode also names: the
// community mirror does not carry technical-docs/, so the PRD alone would name
// a document a Community operator does not have.
const OperatorNotes = "docs/security/decision-shadow-mode.md"

// IdentityCompatNotes is the page a refusal of the identity-compat mode also
// names, for the same reason.
const IdentityCompatNotes = "docs/security/identity-compat-mode.md"

// DecisionMode is the decision mode and its shadow observer's configuration,
// retired by PRD v11 §1.1 and §1.3: the ADR-065 decision plane authors every
// verdict, and nothing compares it with the engines it replaced. The last three
// configured only the observer's compile of the legacy world - how often it
// logged a match, the trust realm of compiled segment groups, and the field a
// legacy static redaction targeted - so with the observer gone, a set value
// would be silently ignored.
var DecisionMode = []string{
	"AXONFLOW_DECISION_SHADOW_MODE",
	"AXONFLOW_DECISION_SHADOW_PLANES",
	"AXONFLOW_DECISION_SHADOW_SAMPLE_RATE",
	"AXONFLOW_DECISION_SHADOW_QUEUE_DEPTH",
	"AXONFLOW_DECISION_SHADOW_WORKERS",
	"AXONFLOW_DECISION_SHADOW_MATCH_LOG_EVERY",
	"AXONFLOW_DECISION_SHADOW_REALM",
	"AXONFLOW_DECISION_SHADOW_CONTENT_TARGET",
}

// MCPDynamicPolicies is the MCP dynamic-policy plane's configuration, retired by
// PRD v11 §1.2 and §1.7: the anchored engine decides the MCP plane's requests,
// and nothing on the agent asks the orchestrator to evaluate an organization's
// tenant dynamic policies for them. The graceful switch let a request through
// when that evaluation was unavailable, which v11 forbids outright (§1.7).
var MCPDynamicPolicies = []string{
	"MCP_DYNAMIC_POLICIES_ENABLED",
	"MCP_DYNAMIC_POLICIES_CONNECTORS",
	"MCP_DYNAMIC_POLICIES_TIMEOUT",
	"MCP_DYNAMIC_POLICIES_GRACEFUL",
}

// FinCrimeScorer is the FinCrime Engine B scorer's configuration, retired with
// the legacy FinCrime engine that called it (PRD v11 §1.2, §5.1): the anchored
// engine decides the FinCrime pack's controls on every plane they bind on, and
// nothing asks the scorer for a risk score. The v10 enterprise compose file set
// the timeout to a non-empty default, so an upgrade that keeps it is refused.
var FinCrimeScorer = []string{
	"AXONFLOW_FINCRIME_SCORER_URL",
	"AXONFLOW_FINCRIME_SCORER_TIMEOUT_MS",
}

// IdentityCompat is the identity-compat mode and its comparison's
// configuration, retired by PRD v11 §1.3: the identity plane alone decides
// whether a credential is admitted, and nothing resolves it the pre-v11 way
// beside it. The last three configured only the comparison - which refusal
// reasons enforce acted on, which credential paths it compared, and how often
// it logged an agreement - so with the comparison gone, a set value would be
// silently ignored.
var IdentityCompat = []string{
	"AXONFLOW_IDENTITY_COMPAT_MODE",
	"AXONFLOW_IDENTITY_COMPAT_ENFORCE_REASONS",
	"AXONFLOW_IDENTITY_COMPAT_PATHS",
	"AXONFLOW_IDENTITY_COMPAT_AGREEMENT_LOG_EVERY",
}

// HITLGrant is the single-use approval grant's lifetime, retired with the grant
// (#4254): /api/request raises no hold since #4253, so nothing mints or spends a
// grant, and an approval hold is the anchored engine's challenge verdict, which
// no grant lifetime bounds (PRD v11 §1.13). The agent validated it at boot until
// then, so a deployment that sets it believes it bounds something.
var HITLGrant = []string{
	"AXONFLOW_HITL_GRANT_TTL_SECONDS",
}

// families is every retired variable Refuse refuses, each family with the
// reason its refusal gives. A variable retired later joins a family here or
// arrives as a new one, and every guard that holds a shipped file or the
// upgrade preflight to the retired set reads this list, so none can miss it.
var families = []struct {
	names  []string
	refuse func(set string, count int) string
}{
	{DecisionMode, func(set string, count int) string {
		return fmt.Sprintf(
			"%s: v11 has no decision mode and no shadow comparison - the ADR-065 decision plane authors every verdict on every enforcing plane, "+
				"and nothing selects or observes another engine (%s §1.1, §5.1; %s). Remove %s from this process's environment; "+
				"it is refused rather than ignored because a deployment that sets it believes it does something",
			set, PRD, OperatorNotes, pluralIt(count))
	}},
	{MCPDynamicPolicies, func(set string, count int) string {
		return fmt.Sprintf(
			"%s: v11 retired the MCP dynamic-policy plane - the anchored engine decides the MCP plane's requests, and an organization's "+
				"tenant dynamic policies no longer decide them (%s §1.2, §1.7, §5.1). Remove %s from this process's environment; "+
				"it is refused rather than ignored because a deployment that sets it believes it does something",
			set, PRD, pluralIt(count))
	}},
	{FinCrimeScorer, func(set string, count int) string {
		return fmt.Sprintf(
			"%s: v11 retired the FinCrime Engine B scorer with the legacy FinCrime engine that called it - the anchored engine decides "+
				"the FinCrime pack's controls, and no plane asks the scorer for a risk score (%s §1.2, §5.1). Remove %s from this process's environment; "+
				"it is refused rather than ignored because a deployment that sets it believes it does something",
			set, PRD, pluralIt(count))
	}},
	{IdentityCompat, func(set string, count int) string {
		return fmt.Sprintf(
			"%s: v11 has no identity-compat mode and no identity comparison - the identity plane alone decides whether a credential is admitted, "+
				"and nothing resolves it the pre-v11 way beside it (%s §1.3, §5.1; %s). Remove %s from this process's environment; "+
				"it is refused rather than ignored because a deployment that sets it believes it does something",
			set, PRD, IdentityCompatNotes, pluralIt(count))
	}},
	{HITLGrant, func(set string, count int) string {
		return fmt.Sprintf(
			"%s: v11 has no single-use approval grant - /api/request raises no hold, so nothing mints or spends a grant, "+
				"and an approval hold is the anchored engine's challenge verdict, which holds where the plane can hold (%s §1.13, §5.1). "+
				"Remove %s from this process's environment; it is refused rather than ignored because a deployment that sets it believes it does something",
			set, PRD, pluralIt(count))
	}},
}

// Refuse returns an error naming every retired variable set to a non-empty
// value, or nil. The caller's contract is to refuse to boot on an error.
func Refuse() error {
	var refusals []string
	for _, f := range families {
		if set := setIn(f.names); len(set) > 0 {
			refusals = append(refusals, f.refuse(strings.Join(set, ", "), len(set)))
		}
	}
	if len(refusals) == 0 {
		return nil
	}
	return errors.New(strings.Join(refusals, "; "))
}

// setIn returns name="value" for every variable in names set to a non-empty
// value.
func setIn(names []string) []string {
	var set []string
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			set = append(set, fmt.Sprintf("%s=%q", name, value))
		}
	}
	return set
}

func pluralIt(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}
