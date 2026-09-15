// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"strings"
	"testing"
)

// TestTheValidatorPlaneClassifierKeepsAllThreeAnswers drives the census's
// per-plane derivation where it can still disagree (#3884).
//
// Over the real legacy_call_sites.tsv every static evaluator is
// validator-bearing, so the census renders validator_planes equal to planes on
// every row and both the bare and the mixed arm are unreachable. A classifier
// collapsed to binary, or to "gated everywhere", would regenerate the same
// census. So the validator-bearing set is supplied here with the shared
// engine's response evaluator bare, and the three answers are asserted plane by
// plane, through the same rendering that writes the census columns. No
// deployment has had that shape: the bare evaluator the census recorded before
// #3963 was the tier engine's EvaluatePolicy, which #4253 deleted with its
// plane, so the table below is synthetic.
func TestTheValidatorPlaneClassifierKeepsAllThreeAnswers(t *testing.T) {
	const callSites = "plane\tevaluator\n" +
		"decide\tEvaluateRequest\n" +
		"policy_test\tEvaluateRequest\n" +
		"policy_test\tEvaluateResponse\n" +
		"orchestrator_response\tEvaluateResponse\n" +
		"wcp\tEvaluateDynamicPolicies\n"
	bareResponse := map[string]bool{"EvaluateRequest": true, "EvaluateResponse": false}

	kind, err := classifyValidatorPlanes(callSites, bareResponse)
	if err != nil {
		t.Fatalf("classifyValidatorPlanes: %v", err)
	}
	want := map[string]planeValidatorKind{
		"decide":                planeValidator,
		"policy_test":           planeMixed,
		"orchestrator_response": planeBare,
	}
	names := map[planeValidatorKind]string{planeBare: "bare", planeValidator: "gated", planeMixed: "mixed"}
	for plane, w := range want {
		if got, ok := kind[plane]; !ok || got != w {
			t.Errorf("plane %q classifies as %s (present=%v), want %s", plane, names[got], ok, names[w])
		}
	}
	if _, ok := kind["wcp"]; ok {
		t.Errorf("wcp has only a dynamic call site and was classified; it reads no static row, so it is not part of this question")
	}

	const planes = "decide,orchestrator_response,policy_test"
	if got := censusValidatorPlanes(planes, kind); got != "decide,policy_test(mixed)" {
		t.Errorf("validator_planes renders %q, want %q; the census would record a gate the bare plane does not have", got, "decide,policy_test(mixed)")
	}
	if got := censusNonValidatorPlanes(planes, kind); got != "orchestrator_response,policy_test(mixed)" {
		t.Errorf("the non-validator planes render %q, want %q", got, "orchestrator_response,policy_test(mixed)")
	}

	// The control: the REAL validator-bearing set over the same table gates
	// every static plane. Without it the assertions above would pass on a
	// classifier that ignored the set and hard-coded the bare plane.
	real, err := classifyValidatorPlanes(callSites, validatorBearingEvaluators)
	if err != nil {
		t.Fatalf("classifyValidatorPlanes with the real set: %v", err)
	}
	for _, plane := range []string{"decide", "policy_test", "orchestrator_response"} {
		if real[plane] != planeValidator {
			t.Errorf("with every static evaluator validator-bearing, plane %q classifies as %s, want gated", plane, names[real[plane]])
		}
	}

	// And the anti-vacuity refusal: a table that names no site for one of the
	// static evaluators would classify nothing about it.
	if _, err := classifyValidatorPlanes(strings.Replace(callSites, "EvaluateResponse", "Renamed", -1), bareResponse); err == nil ||
		!strings.Contains(err.Error(), `names no "EvaluateResponse" call site`) {
		t.Errorf("a table with no EvaluateResponse site was not refused as vacuous: %v", err)
	}
}
