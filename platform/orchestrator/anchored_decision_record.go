// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
)

// anchoredDecision is what an anchored seam records about one decision (PRD v11
// §5.7): the plane's own label, the engine that decided, the type of principal
// it was decided for, the digest of the policy set that decided, and the
// engine's decision id. The WCP step gate, the multi-agent plane and the two
// route seams stamp it on their audit rows; the response plane records the same
// members through RedactionInfo.
type anchoredDecision struct {
	Plane        string
	Engine       string
	SubjectType  string
	PolicyBundle string
	DecisionID   string
}

// anchoredDecisionFor is the record a seam's verdict gives under scope. A nil
// verdict is a decision the plane could not reach, because it failed closed
// before the engine answered: the plane and the engine are still named, and
// nothing the engine did not produce is.
func anchoredDecisionFor(scope legacycompile.EnforcementScope, v *anchoredenforcer.Verdict) *anchoredDecision {
	d := &anchoredDecision{Plane: scope.String(), Engine: anchoredenforcer.EngineAnchored}
	if v == nil {
		return d
	}
	d.SubjectType = v.SubjectType
	if v.Act != nil {
		d.PolicyBundle = v.Act.PolicyBundle
	}
	if v.Decision != nil {
		d.DecisionID = v.Decision.DecisionID
	}
	return d
}

// stampUnsetDetails writes each non-empty member onto details unless the writer
// already set it. A member left empty is omitted rather than written empty, and
// an entry the writer set wins. Every anchored stamp goes through it.
func stampUnsetDetails(details map[string]interface{}, members map[string]string) {
	for key, value := range members {
		if _, set := details[key]; value != "" && !set {
			details[key] = value
		}
	}
}

// stampAnchoredDecision writes d onto entry: the plane and decision_id columns,
// and engine, subject_type, policy_bundle and decision_id in policy_details. A
// member d does not carry is omitted, and a value the writer already set wins,
// as stampResponsePlaneDecision does for the response plane.
func stampAnchoredDecision(entry *AuditEntry, d *anchoredDecision) {
	if entry == nil || d == nil {
		return
	}
	if entry.Plane == "" {
		entry.Plane = d.Plane
	}
	if entry.DecisionID == "" {
		entry.DecisionID = d.DecisionID
	}
	if entry.PolicyDetails == nil {
		entry.PolicyDetails = map[string]interface{}{}
	}
	stampUnsetDetails(entry.PolicyDetails, map[string]string{
		"engine":        d.Engine,
		"subject_type":  d.SubjectType,
		"policy_bundle": d.PolicyBundle,
		"decision_id":   d.DecisionID,
	})
}

// stampStepGateDecision records the step gate's anchored decision on its
// evaluation, from which the service writes the answer and the audit row.
func stampStepGateDecision(e *workflow_control.StepGateEvaluation, v *anchoredenforcer.Verdict) *workflow_control.StepGateEvaluation {
	if e == nil {
		return nil
	}
	d := anchoredDecisionFor(wcpSeamScope, v)
	e.Plane, e.Engine, e.SubjectType, e.PolicyBundle, e.EngineDecisionID = d.Plane, d.Engine, d.SubjectType, d.PolicyBundle, d.DecisionID
	return e
}

// anchoredDecision is the record a route's blocked audit row carries. Both
// routes decide under the workflow control plane's scope.
func (d routeRequestDecision) anchoredDecision() *anchoredDecision {
	return &anchoredDecision{
		Plane:        wcpSeamScope.String(),
		Engine:       routeRequestEngine,
		SubjectType:  d.subjectType,
		PolicyBundle: d.policyBundle,
		DecisionID:   d.decisionID,
	}
}
