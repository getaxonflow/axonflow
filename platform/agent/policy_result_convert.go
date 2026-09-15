// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"github.com/prometheus/client_golang/prometheus"

	sharedpolicy "axonflow/platform/shared/policy"
)

// policyStoredActionDisplaced counts matched policies whose ROW-stored action
// was resolved DOWNWARD by an organization's recorded detection override (#3360,
// #3961): the row says block (or redact/require_approval) but the override
// resolved something weaker. Upward displacement (an override tightening a warn
// row) is the override doing its job and not counted. Since v11 a recorded
// override is the only thing that can displace a stored action - no environment
// variable or profile does - so this counts exactly the weakening an
// organization chose.
var policyStoredActionDisplaced = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_agent_policy_stored_action_displaced_total",
		Help: "Matched policies whose stored action was weakened by an organization's recorded detection override (category/stored/resolved)",
	},
	[]string{"category", "stored", "resolved"},
)

func init() {
	prometheus.MustRegister(policyStoredActionDisplaced)
}

// convertSharedResultToStatic converts a shared policy engine RequestResult
// to a StaticPolicyResult for backward compatibility with existing handler code.
// This bridges the shared engine result to the StaticPolicyResult type used by handlers.
func convertSharedResultToStatic(result *sharedpolicy.RequestResult) *StaticPolicyResult {
	if result == nil {
		return &StaticPolicyResult{
			Blocked:           false,
			TriggeredPolicies: []string{},
			ChecksPerformed:   []string{"shared_policy_engine"},
		}
	}

	staticResult := &StaticPolicyResult{
		Blocked:          result.Blocked,
		Reason:           result.BlockReason,
		ProcessingTimeMs: result.ProcessingTimeMs,
		ChecksPerformed:  []string{"shared_policy_engine"},
		EvaluationError:  result.EvaluationError, // #2862: propagate fail-closed availability failure
	}

	// Convert matched policies to triggered policy IDs (and carry the
	// evaluation-time display names alongside, #3365, so the audit writers can
	// stamp policy_names for the same ids).
	staticResult.PolicyNames = policyNamesFromMatches(result.MatchedPolicies)
	for _, match := range result.MatchedPolicies {
		staticResult.TriggeredPolicies = append(staticResult.TriggeredPolicies, match.PolicyID)
		// Capture severity from the blocking policy
		if result.Blocked && result.BlockedBy != nil && match.PolicyID == result.BlockedBy.PolicyID {
			staticResult.Severity = string(result.BlockedBy.Severity)
		}
	}

	// A non-blocking PII match whose RESOLVED action is redact requires
	// redaction. The action on the match already carries the organization's
	// recorded pii override (engine.go sets match.Action = override), so keying
	// on it is override-accurate, and warn/log - and every other action -
	// attach none (#2965's sibling fix). Category membership is the shared,
	// prefix-based sharedpolicy.IsPIIPolicyCategory, so pii-indonesia is
	// covered. That a matched control is never a silent allow is the anchored
	// engine's to say now (advisoryReasons), since it authors the verdict.
	for _, match := range result.MatchedPolicies {
		if result.Blocked || !sharedpolicy.IsPIIPolicyCategory(match.Category) {
			continue
		}
		if match.Action == sharedpolicy.ActionRedact {
			staticResult.RequiresRedaction = true
		}
	}

	recordStoredActionDisplacement(result)

	return staticResult
}

// recordStoredActionDisplacement records every DOWNWARD displacement in a
// shared engine result (#3360) - a matched policy whose stored action an
// organization's recorded override weakened (block resolved to
// redact/warn/log, redact resolved to warn/log, ...). Since v11 that override
// is the only thing that can displace a stored action (#3961); before, the
// profile and the *_ACTION variables did it for every organization and the
// policy row said block while nothing blocked (the #3360 report). Skipped
// when the request is blocked (nothing was weakened into an allow) and for
// upward displacement (an override tightening a warn row). Every plane that
// evaluates through the shared engine records it: through
// convertSharedResultToStatic, or directly where the anchored engine authors
// the verdict and nothing converts (the OpenAI-compatible route).
func recordStoredActionDisplacement(result *sharedpolicy.RequestResult) {
	if result == nil || result.Blocked {
		return
	}
	displacedSeen := make(map[string]bool, len(result.MatchedPolicies))
	for _, match := range result.MatchedPolicies {
		if match.PolicyID == "" || displacedSeen[match.PolicyID] {
			continue
		}
		if match.StoredAction == "" || match.StoredAction == match.Action {
			continue
		}
		if ActionRestrictiveness(OverrideAction(match.StoredAction)) <= ActionRestrictiveness(OverrideAction(match.Action)) {
			continue
		}
		displacedSeen[match.PolicyID] = true
		policyStoredActionDisplaced.WithLabelValues(
			string(match.Category), string(match.StoredAction), string(match.Action)).Inc()
	}
}
