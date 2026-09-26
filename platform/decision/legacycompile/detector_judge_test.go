// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"testing"

	"axonflow/platform/decision/pdp"
)

const (
	judgeDropTable = "signal.detector.drop__table__prevention"
	judgeEmail     = "signal.detector.sys__pii__email"
	judgeTruncate  = "signal.detector.truncate__prevention"
)

func judgeOn(t *testing.T, plane Plane, phase Phase) *ScopeDetectorJudge {
	t.Helper()
	j, err := NewScopeDetectorJudge(MustScopeFor(plane, phase))
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func reads(paths ...string) pdp.Policy {
	var ops []pdp.Condition
	for _, p := range paths {
		ops = append(ops, pdp.Compare(p, pdp.OpEq, true))
	}
	if len(ops) == 1 {
		return pdp.Policy{Where: ops[0]}
	}
	return pdp.Policy{Where: pdp.Or(ops...)}
}

// THE SHIPPED ENTRY KEEPS ALL THREE ARMS (#4249 row 5674230432): the shipped
// corpus's restriction has always dropped a control whose detector a scope
// loads and does not pass the category of, and still does. decide loads DROP
// TABLE (the census lists it) and passes no dangerous_queries category.
func TestTheShippedEntryAppliesTheLoadPhaseAndCategoryArms(t *testing.T) {
	for _, tc := range []struct {
		plane Plane
		want  DetectorArm
	}{
		{PlaneProxyRequest, DetectorArmKept},
		{PlaneDecide, DetectorArmCategory},
		{PlaneOrchestratorResponse, DetectorArmCategory},
		{PlaneWCP, DetectorArmLoad},
		{PlaneOrchestratorRequest, DetectorArmLoad},
	} {
		if got := judgeOn(t, tc.plane, "").Judge(reads(judgeDropTable)).Arm; got != tc.want {
			t.Errorf("Judge(DROP TABLE) on %s = %s, want %s", tc.plane, got, tc.want)
		}
	}
	if got := judgeOn(t, PlaneDecide, "").Judge(pdp.Policy{Where: pdp.True()}).Arm; got != DetectorArmUnjudged {
		t.Errorf("a policy reading no censused detector = %s, want unjudged", got)
	}
}

// ALL, NOT FIRST-MATCH, on the shipped entry. orchestrator_response decides the
// e-mail detector and not TRUNCATE (category); a policy reading both sorts the
// e-mail path first, so a first-match judge would keep it.
func TestTheShippedEntryKeepsAPolicyOnlyWhereEveryDetectorItReadsRuns(t *testing.T) {
	if !(judgeEmail < judgeTruncate) {
		t.Fatalf("PREMISE: %s must sort first, or this cell cannot tell ALL from first-match", judgeEmail)
	}
	j := judgeOn(t, PlaneOrchestratorResponse, "")
	if got := j.Judge(reads(judgeEmail)).Arm; got != DetectorArmKept {
		t.Fatalf("PREMISE: orchestrator_response decides the e-mail detector alone: %s", got)
	}
	v := j.Judge(reads(judgeEmail, judgeTruncate))
	if v.Runs() || v.Path != judgeTruncate || v.Arm != DetectorArmCategory {
		t.Fatalf("both detectors on orchestrator_response = %+v; want dropped on the category arm naming %s", v, judgeTruncate)
	}
	if v := judgeOn(t, PlaneProxyRequest, "").Judge(reads(judgeEmail, judgeTruncate)); !v.Runs() {
		t.Fatalf("both detectors on proxy_request = %+v; want kept", v)
	}
}

// THE ORGANIZATION ENTRY APPLIES THE LOAD ARM ONLY, AND ONLY WHERE NO REGISTRY
// DETECTOR RUNS (master's ruling on row 5674230432): on wcp, map and
// orchestrator_request a control reading a registry detector is dropped; on
// every scope that runs registry detectors it is not judged, so a control
// decide drops on the category arm stays as it was there.
func TestTheOrganizationEntryAppliesTheLoadArmOnlyWhereNoRegistryDetectorRuns(t *testing.T) {
	for _, tc := range []struct {
		plane    Plane
		runsNone bool
		want     DetectorArm
	}{
		{PlaneWCP, true, DetectorArmLoad},
		{PlaneMAP, true, DetectorArmLoad},
		{PlaneOrchestratorRequest, true, DetectorArmLoad},
		// THE ARM'S REACH IS FIVE PLANES, NOT THREE (master R3 round 1 on
		// #4394, LOW-1): runsNone is "the census lists no detector for this
		// plane", and the two operator tools are in that set as well. It
		// changes nothing today because neither has a registered SEAM: the
		// agent's seamFor answers not-wired for them, which is what
		// TestAScopeWithNoSeamFailsClosed asserts by taking
		// MustScopeFor(PlanePolicyTest) as its example of a scope with none
		// (platform/agent/decision_enforcing_seam_unit_test.go). No request is
		// enforced on them, so no organization document is activated there -
		// but the judge answers for them, and the count in any prose about
		// this arm is five.
		{PlanePolicySimulation, true, DetectorArmLoad},
		{PlanePolicyTest, true, DetectorArmLoad},
		{PlaneDecide, false, DetectorArmNotApplied},
		{PlaneOrchestratorResponse, false, DetectorArmNotApplied},
		{PlaneProxyRequest, false, DetectorArmNotApplied},
	} {
		j := judgeOn(t, tc.plane, "")
		if j.RunsNoRegistryDetector() != tc.runsNone {
			t.Errorf("%s RunsNoRegistryDetector = %v, want %v", tc.plane, j.RunsNoRegistryDetector(), tc.runsNone)
		}
		if got := j.JudgeOrganization(reads(judgeDropTable)).Arm; got != tc.want {
			t.Errorf("JudgeOrganization(DROP TABLE) on %s = %s, want %s", tc.plane, got, tc.want)
		}
		if got := j.JudgeOrganization(pdp.Policy{Where: pdp.True()}).Arm; got != DetectorArmUnjudged {
			t.Errorf("JudgeOrganization(no detector) on %s = %s, want unjudged", tc.plane, got)
		}
	}
	// THE TWO ENTRIES DISAGREE EXACTLY WHERE THE RULING SAYS: decide, category.
	d := judgeOn(t, PlaneDecide, "")
	if d.Judge(reads(judgeDropTable)).Runs() || !d.JudgeOrganization(reads(judgeDropTable)).Runs() {
		t.Fatal("on decide the shipped entry must drop DROP TABLE (category) and the organization entry must not judge it")
	}
}
