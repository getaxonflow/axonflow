// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// TODAY'S SHAPE ON AN AGENT PLANE, MEASURED (#4249 row 5674230432, master's
// ruling on its reach). /api/v1/decide LOADS the DROP TABLE detector (the
// census lists decide) and passes no dangerous_queries category to the
// evaluator, so the row never runs there and no observation states it. An
// organization control reading it is therefore UNKNOWN on decide and WITHHOLDS
// the request as unknown_constraint - the same defect the orchestrator planes
// had. The organization arm of the fix applies only where no registry detector
// runs - which planes those are is derived from the census by
// legacycompile.ScopeDetectorJudge and is never listed here - so on decide,
// where detectors DO run, this shape is kept, and this cell pins it as a
// measured fact for the row that decides it separately.
//
// The positive control is the same constraint over a detector decide DOES run
// (the e-mail detector, category admitted): it is decided, so the withhold
// above is the detector not running and not the document.
func TestAnOrganizationControlOnADetectorDecideDoesNotRunIsWithheldThereToday(t *testing.T) {
	cases := []struct {
		name, detector string
		withheld       bool
	}{
		{"drop table, a category decide does not pass: withheld unknown", "signal.detector.drop__table__prevention", true},
		{"e-mail, a category decide passes: decided", "signal.detector.sys__pii__email", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", "enterprise")
			origSecret := jwtSecret
			jwtSecret = []byte(testJWTSecret)
			t.Cleanup(func() { jwtSecret = origSecret })
			enfNoCircuitBreaker(t)
			enfInstallDetectors(t, nil, nil)
			rutInstallCache(t, enfOrgPublished, false)

			const id = "ceiling.detector_4249"
			completion := "Action::" + authoringcatalog.ActionLLMCompletion
			now := time.Now().UTC()
			doc := pdp.Document{
				Root: pdp.RootOrganization, Version: 1,
				Attributes: []pdp.AttributeSchema{{Path: tc.detector, Type: pdp.TypeBoolean}},
				Policies: []pdp.Policy{{
					ID: id, Name: enfConstraintName(id), Authority: contract.AuthorityConstraint, Root: pdp.RootOrganization,
					Scope:   pdp.Scope{Organization: true},
					Actions: pdp.ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, completion)}},
					Where:   pdp.Compare(tc.detector, pdp.OpEq, true),
				}},
			}
			fixtures := []authoring.Fixture{{
				Name: "the detector fired",
				Attributes: contract.AttributeSet{
					"action.id":   contract.Known(completion, contract.ProvPlatform, 1, now),
					"action.tags": contract.Known([]any{"stage:llm"}, contract.ProvPlatform, 1, now),
					"args.query":  contract.Known("hello", contract.ProvCaller, 1, now),
					tc.detector:   contract.Known(true, contract.ProvDetector, 1, now),
				},
				Expect: map[string]pdp.Verdict{id: pdp.VerdictMatch},
			}}
			enfInstallSeam(t, enfPublishPolicyDocumentAs(t, authoring.EditionEnterprise, enfSnapshot(t), doc, fixtures))

			r := enfDecide(t, enfOrgPublished, false, DecisionStageLLM, "hello there")
			named := strings.Contains(string(r.raw), string(contract.ReasonUnknownConstraint)) && strings.Contains(string(r.raw), id)
			if tc.withheld && (r.str(t, "verdict") == VerdictAllow || !named) {
				t.Fatalf("HTTP %d verdict %q; want the request withheld as %s naming %s. body=%s", r.code, r.str(t, "verdict"), contract.ReasonUnknownConstraint, id, r.raw)
			}
			if !tc.withheld && (r.str(t, "verdict") != VerdictAllow || named) {
				t.Fatalf("HTTP %d verdict %q; want the clean request decided and allowed. body=%s", r.code, r.str(t, "verdict"), r.raw)
			}
		})
	}
}
