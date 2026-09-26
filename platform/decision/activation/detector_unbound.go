// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"fmt"
	"slices"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// AN ORGANIZATION'S CONTROL BINDS ONLY WHERE THE DETECTORS IT READS RUN (#4249
// row 5674230432).
//
// A control that reads a registry detector (a signal.detector.* path the
// shipped census records) is decided only on a scope whose call sites evaluate
// that detector. Anywhere else the detector is UNKNOWN. On the three scopes
// that run NO registry detector - the orchestrator request plane
// (/api/v1/process, /api/v1/plan/execute), the workflow step gate and the
// multi-agent plane - such a control therefore withheld every request it
// applied to as unknown_constraint, whatever its content.
//
// The shipped corpus has always been restricted by this question
// (restrictToScope, legacycompile.ScopeDetectorJudge.Judge). This arm applies
// the judge's ORGANIZATION entry (JudgeOrganization) to the organization's own
// document: on a scope that runs no registry detector, a control that reads one
// is left off the organization root through the omission binds_on uses, and
// recorded as a DetectorUnboundControl naming the detector and the planes that
// run it. On a scope that runs registry detectors it changes nothing: a control
// whose detector that scope drops on its category or phase arm is decided
// unknown and withheld there as before (a separate #4249 row). Publication
// warns of the same answer, from the same entry
// (authoring.CodeDetectorControlUnboundOnPlanes).

// DetectorUnboundControl is one control of the active document left off this
// scope because the scope does not run a registry detector it reads.
type DetectorUnboundControl struct {
	// ID is the control's policy id.
	ID string `json:"id"`
	// Detector is the signal path of the detector that is not run here (the
	// first, in path order, of those the control reads that fail).
	Detector string `json:"detector"`
	// Planes are the planes the detector census says run it.
	Planes []string `json:"planes"`
	// Arm is which arm of the judge left it off: load, the one arm the
	// organization entry applies (the scope runs no registry detector).
	Arm string `json:"arm"`
}

// RefusalDetectorCarriedOffScope is the code of the backstop after
// composition: the organization root would carry a policy that reads a
// registry detector this scope does not run. It holds by construction
// (organizationDetectorUnbound feeds the omission), so it names a defect.
const RefusalDetectorCarriedOffScope = "DETECTOR_CARRIED_OFF_SCOPE"

// organizationDetectorUnbound judges each of doc's controls on the judge's
// scope, in the document's order, and returns those the scope does not decide.
//
// IT JUDGES EVERY CONTROL, including one whose actions this scope never
// presents, where publication warns only about the scopes that present an
// action the control selects. The two populations therefore differ, in the
// harmless direction: a control this scope could not reach anyway is recorded
// as left off it rather than silently absent, and nothing an author reads at
// publish claims otherwise.
// A control already placed by another arm (placed: the ids its binds_on leaves
// off, and the organization template's controls the template's arm places by
// id) is not judged here, so each control is recorded once and the template's
// copies compose exactly as before this arm existed.
func organizationDetectorUnbound(judge *legacycompile.ScopeDetectorJudge, doc *pdp.Document, placed []string) []DetectorUnboundControl {
	var out []DetectorUnboundControl
	for _, p := range doc.Policies {
		if slices.Contains(placed, p.ID) {
			continue
		}
		j := judge.JudgeOrganization(p)
		if j.Runs() {
			continue
		}
		out = append(out, DetectorUnboundControl{ID: p.ID, Detector: j.Path, Planes: j.Planes, Arm: string(j.Arm)})
	}
	return out
}

// detectorUnboundIDs are the ids of controls.
func detectorUnboundIDs(controls []DetectorUnboundControl) []string {
	out := make([]string, 0, len(controls))
	for _, c := range controls {
		out = append(out, c.ID)
	}
	return out
}

// refuseDetectorCarriedOffScope is the backstop after composition: no policy
// of the organization root this engine activates may read a registry detector
// this scope does not run. A policy that did would be UNKNOWN on every request
// and refuse it, which is the defect the omission exists to prevent.
func refuseDetectorCarriedOffScope(judge *legacycompile.ScopeDetectorJudge, org *pdp.Document) error {
	if org == nil {
		return nil
	}
	for _, p := range org.Policies {
		if j := judge.JudgeOrganization(p); !j.Runs() {
			return &pdp.ActivationRefusal{Code: RefusalDetectorCarriedOffScope, Detail: fmt.Sprintf(
				"the organization root on %s carries control %q, which reads detector %s; the census says it runs on %v, "+
					"and this scope is not one of them (%s arm)", judge.Scope(), p.ID, j.Path, j.Planes, j.Arm)}
		}
	}
	return nil
}

// detectorUnboundReason is the sentence the activation's restriction reason
// gains when the organization's document has controls this arm left off, and
// empty when it has none, so an activation with none reads as it did.
func detectorUnboundReason(scope legacycompile.EnforcementScope, controls []DetectorUnboundControl) string {
	if len(controls) == 0 {
		return ""
	}
	return fmt.Sprintf("; %d of the organization document's controls read a registry detector, which %s does not run "+
		"(it runs none), and are left off it rather than decided unknown (DetectorUnboundControls)", len(controls), scope)
}
