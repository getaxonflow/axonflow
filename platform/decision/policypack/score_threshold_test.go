// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policypack_test

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/policypack"
)

// A pack's control over an external scorer's signal (#3330), field by field.

func scoreSource() *policypack.Source {
	return &policypack.Source{
		ID: "scored", Version: 2,
		Approval: &policypack.ApproverPool{Quorum: 1, Group: "scored-approvers"},
		Scores: []policypack.ScoreThreshold{{
			ID: "ml_stepup", Name: "ML Step-Up", Category: "fincrime", Severity: "high", Phase: "request",
			Signal: "fincrime_fraud", Threshold: 0.011591929942369461,
			ThresholdRule: "chosen to flag at most 1% of transactions on the validation partition", Description: "Scored high.",
		}},
	}
}

func TestAScoreControlCompilesToAHoldThatAMissingScoreDoesNotApply(t *testing.T) {
	doc, err := policypack.Compile(scoreSource(), []string{"Group::r:scored-approvers"})
	if err != nil {
		t.Fatal(err)
	}
	if errs := doc.Validate(); len(errs) > 0 {
		t.Fatalf("the compiled document does not validate as the engine reads it: %v", errs)
	}
	if len(doc.Policies) != 1 || len(doc.Attributes) != 1 {
		t.Fatalf("%d policies, %d attributes; want one of each", len(doc.Policies), len(doc.Attributes))
	}
	p, a := doc.Policies[0], doc.Attributes[0]
	path := policypack.ScorerSignalPath("fincrime_fraud")
	if path != "signal.scorer.fincrime__fraud" {
		t.Fatalf("signal path %q", path)
	}
	for _, check := range []struct {
		what string
		ok   bool
	}{
		{"the id is the pack's", p.ID == policypack.PolicyID("scored", "ml_stepup")},
		{"a requirement, never a constraint: a score cannot author a block", p.Authority == contract.AuthorityRequirement},
		{"mandatory, so it holds", p.Mandatory},
		{"gating_risk, the class the combiner gives it", p.Assurance == pdp.AssuranceGatingRisk},
		{"one mandatory approval_challenge attributed to itself", len(p.Obligations) == 1 && p.Obligations[0].Type == contract.ObApprovalChallenge &&
			p.Obligations[0].Mandatory && p.Obligations[0].SourcePolicy == p.ID},
		{"the pool is the one given", len(p.Obligations) == 1 && p.Obligations[0].Params["eligible"] == "Group::r:scored-approvers"},
		{"a >= comparison of the signal against the threshold", p.Where.Kind == pdp.CondCompare && p.Where.Path == path &&
			p.Where.Op == pdp.OpGe && p.Where.Literal == 0.011591929942369461},
		{"a missing score is NO MATCH", p.Where.OnAbsent == pdp.AbsentIsNoMatch},
		{"the attribute is an optional number", a.Path == path && a.Type == pdp.TypeNumber && a.Optional},
		{"the description carries the threshold and its rule", strings.Contains(p.Description, "0.011591929942369461") &&
			strings.Contains(p.Description, "chosen to flag at most 1% of transactions on the validation partition")},
	} {
		if !check.ok {
			t.Errorf("%s: %+v", check.what, p)
		}
	}
}

func TestAScoreControlIsReadBackFromItsPack(t *testing.T) {
	src := scoreSource()
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := policypack.Render(src)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := policypack.Load(raw, committed)
	if err != nil {
		t.Fatal(err)
	}
	id := policypack.PolicyID("scored", "ml_stepup")
	if sc, ok := pack.ScoreControl(id); !ok || sc.Signal != "fincrime_fraud" {
		t.Fatalf("ScoreControl(%s) = %+v, %v", id, sc, ok)
	}
	if phase, ok := pack.ControlPhase(id); !ok || phase != "request" {
		t.Fatalf("ControlPhase(%s) = %q, %v", id, phase, ok)
	}
	if _, ok := pack.ScoreControl(policypack.PolicyID("scored", "nope")); ok {
		t.Fatal("an id the pack does not compile was read as a score control")
	}
}

func TestAScoreControlIsRefusedFieldByField(t *testing.T) {
	// POSITIVE CONTROL: the unmodified source validates, so each refusal below
	// is the field's own.
	if err := scoreSource().Validate(); err != nil {
		t.Fatalf("the base source is refused: %v", err)
	}
	for _, tc := range []struct {
		name, want string
		edit       func(s *policypack.Source)
	}{
		{"no id", "has no id", func(s *policypack.Source) { s.Scores[0].ID = "" }},
		{"no name", "needs a name", func(s *policypack.Source) { s.Scores[0].Name = "" }},
		{"no category", "needs a name", func(s *policypack.Source) { s.Scores[0].Category = "" }},
		{"a response phase", "request phase only", func(s *policypack.Source) { s.Scores[0].Phase = "response" }},
		{"a both phase", "request phase only", func(s *policypack.Source) { s.Scores[0].Phase = "both" }},
		{"a signal with a dot", "not one lowercase identifier", func(s *policypack.Source) { s.Scores[0].Signal = "fincrime.fraud" }},
		{"an uppercase signal", "not one lowercase identifier", func(s *policypack.Source) { s.Scores[0].Signal = "Fraud" }},
		{"a zero threshold", "strictly between 0 and 1", func(s *policypack.Source) { s.Scores[0].Threshold = 0 }},
		{"a threshold of one", "strictly between 0 and 1", func(s *policypack.Source) { s.Scores[0].Threshold = 1 }},
		{"a negative threshold", "strictly between 0 and 1", func(s *policypack.Source) { s.Scores[0].Threshold = -0.2 }},
		{"a NaN threshold", "strictly between 0 and 1", func(s *policypack.Source) { s.Scores[0].Threshold = math.NaN() }},
		{"no threshold rule", "threshold_rule", func(s *policypack.Source) { s.Scores[0].ThresholdRule = "  " }},
		{"no approval pool", "no approval_pool", func(s *policypack.Source) { s.Approval = nil }},
		{"two controls on one signal", "read by two score controls", func(s *policypack.Source) {
			second := s.Scores[0]
			second.ID = "ml_stepup_2"
			s.Scores = append(s.Scores, second)
		}},
		{"an id a detector already has", "appears twice", func(s *policypack.Source) {
			s.Detectors = []policypack.Detector{{ID: "ml_stepup", Name: "n", Category: "fincrime", Severity: "high", Phase: "request", Action: "block", Pattern: "x"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := scoreSource()
			tc.edit(s)
			err := s.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v; want a refusal containing %q", err, tc.want)
			}
		})
	}
	t.Run("a pack with neither detectors nor scores", func(t *testing.T) {
		s := scoreSource()
		s.Scores = nil
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "no detector and no score control") {
			t.Fatalf("err %v", err)
		}
	})
}
