// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// WHERE A CONTROL THAT READS A REGISTRY DETECTOR WILL BIND (#4249 row
// 5674230432).
//
// Activation leaves an organization's control that reads a registry detector
// off each scope that runs NO registry detector - the workflow step gate, the
// multi-agent plane and the orchestrator request plane - where it would
// otherwise withhold every request (activation's DetectorUnboundControls), by
// legacycompile.ScopeDetectorJudge.JudgeOrganization. Publication asks the SAME
// entry over the scopes the control binds on - those its binds_on names, or,
// when binds_on is absent, every scope that presents an action it selects - so
// the author reads at publish the answer activation will act on:
//
//   - some of those scopes run no registry detector: a WARNING naming them
//     (CodeDetectorControlUnboundOnPlanes), because the control still binds on
//     the others;
//   - binds_on names scopes and EVERY one of them runs no registry detector: a
//     REFUSAL (CodeDetectorControlBindsNowhere), because the control would
//     bind nowhere.
//
// Absent binds_on is never refused: it is what every document published before
// #4371 means. A scope that runs registry detectors is not judged here (the
// organization entry does not apply there).

// scopeJudges caches one judge per scope. The census and the plane model are
// compiled into the binary, so a judge built once answers every publication.
var scopeJudges sync.Map // scope string -> *legacycompile.ScopeDetectorJudge

func judgeFor(scope string) (*legacycompile.ScopeDetectorJudge, error) {
	if j, ok := scopeJudges.Load(scope); ok {
		return j.(*legacycompile.ScopeDetectorJudge), nil
	}
	plane, phase, _ := strings.Cut(scope, ":")
	s, err := legacycompile.ScopeFor(legacycompile.Plane(plane), legacycompile.Phase(phase))
	if err != nil {
		return nil, err
	}
	j, err := legacycompile.NewScopeDetectorJudge(s)
	if err != nil {
		return nil, err
	}
	scopeJudges.Store(scope, j)
	return j, nil
}

// validateDetectorScopes applies the rule above to one policy. reached is the
// actions its selector reaches; a scope no reached action presents is one the
// control never binds on, and one that is not an enforcing scope is refused
// elsewhere (CodePlaneNotDeclared), so neither is judged here.
func validateDetectorScopes(p pdp.Policy, reached []pdp.ActionEntry) Findings {
	if p.BindsOn != nil && len(*p.BindsOn) == 0 {
		return nil // CodeBindsOnEmpty
	}
	presented := map[string]bool{}
	for _, a := range reached {
		for _, s := range a.Planes {
			presented[s] = true
		}
	}
	var scopes []string
	if p.BindsOn == nil {
		for s := range presented {
			scopes = append(scopes, s)
		}
	} else {
		for _, s := range *p.BindsOn {
			if presented[s] && !containsString(scopes, s) {
				scopes = append(scopes, s)
			}
		}
	}
	sort.Strings(scopes)
	var notRun []string
	detector := ""
	judged := 0
	for _, s := range scopes {
		j, err := judgeFor(s)
		if err != nil {
			continue // not an enforcing scope this model declares; refused elsewhere
		}
		judged++
		v := j.JudgeOrganization(p)
		if v.Arm == legacycompile.DetectorArmUnjudged {
			return nil // reads no registry detector
		}
		if !v.Runs() {
			notRun = append(notRun, s)
			if detector == "" {
				detector = v.Path
			}
		}
	}
	if len(notRun) == 0 {
		return nil
	}
	var out Findings
	if len(notRun) == judged {
		// EVERY scope it would apply on runs no registry detector, so it binds
		// nowhere. Named by binds_on that is the author's own list and a
		// REFUSAL; reached by an absent binds_on it is a warning, because
		// absent is what every document published before #4371 means and must
		// stay publishable - but the sentence must not say "some", which is the
		// one thing it is not.
		if p.BindsOn != nil {
			return append(out, newFinding(CodeDetectorControlBindsNowhere, p.ID, fmt.Sprintf(
				"binds_on names %v, none of which runs any registry detector, and the control reads %s; it would bind nowhere", notRun, detector)))
		}
		return append(out, newFinding(CodeDetectorControlUnboundOnPlanes, p.ID, fmt.Sprintf(
			"the control reads registry detector %s, and NONE of the planes it would apply on (%v) runs any registry detector, so it binds nowhere", detector, notRun)))
	}
	return append(out, newFinding(CodeDetectorControlUnboundOnPlanes, p.ID, fmt.Sprintf(
		"the control reads registry detector %s, and %v do not run any registry detector, so it does not bind there", detector, notRun)))
}
