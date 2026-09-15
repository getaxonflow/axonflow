// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

// TestDeriveAssuranceFollowsTheCombinersFailureSemantics pins the mapping
// assurance.go documents, one shape at a time.
func TestDeriveAssuranceFollowsTheCombinersFailureSemantics(t *testing.T) {
	signal := Compare("signal.detector.probe", OpEq, true)
	deterministic := Compare("args.amount_cents", OpGt, 10)
	cases := []struct {
		name      string
		policy    Policy
		want      AssuranceClass
		isControl bool
	}{
		{"a permission is not a control", Policy{Authority: contract.AuthorityPermission, Where: signal}, "", false},
		{"a constraint over a detector is gating risk", Policy{Authority: contract.AuthorityConstraint, Where: signal}, AssuranceGatingRisk, true},
		{"a constraint over caller input is enforcement", Policy{Authority: contract.AuthorityConstraint, Where: deterministic}, AssuranceEnforcement, true},
		{"a mandatory requirement over a detector is gating risk", Policy{Authority: contract.AuthorityRequirement, Mandatory: true, Where: signal}, AssuranceGatingRisk, true},
		{"a mandatory requirement over caller input is enforcement", Policy{Authority: contract.AuthorityRequirement, Mandatory: true, Where: deterministic}, AssuranceEnforcement, true},
		{"a non-mandatory requirement is advisory, whatever it reads", Policy{Authority: contract.AuthorityRequirement, Where: signal}, AssuranceAdvisory, true},
		{"an inspection is advisory", Policy{Authority: contract.AuthorityInspection, Where: signal}, AssuranceAdvisory, true},
		{"a signal read in the exception clause still gates", Policy{Authority: contract.AuthorityConstraint, Where: deterministic, Unless: &signal}, AssuranceGatingRisk, true},
		{"an undeclared authority is not a control", Policy{Authority: contract.Authority("veto"), Where: signal}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, isControl := DeriveAssurance(tc.policy)
			if got != tc.want || isControl != tc.isControl {
				t.Fatalf("DeriveAssurance = (%q, %v), want (%q, %v)", got, isControl, tc.want, tc.isControl)
			}
		})
	}
}

// TestADeclaredAssuranceClassIsHeldToThePolicyInEveryDirection asserts the
// refusal names which way the declaration is wrong, because the remedy differs.
func TestADeclaredAssuranceClassIsHeldToThePolicyInEveryDirection(t *testing.T) {
	signal := Compare("signal.detector.probe", OpEq, true)
	deterministic := Compare("args.amount_cents", OpGt, 10)
	cases := []struct {
		name   string
		policy Policy
		rule   string
		detail string
	}{
		{"advisory on a control that denies", Policy{ID: "p", Authority: contract.AuthorityConstraint, Where: signal, Assurance: AssuranceAdvisory},
			RuleAssuranceMismatch, "an advisory control cannot return deny"},
		{"gating risk on a control that is skipped", Policy{ID: "p", Authority: contract.AuthorityRequirement, Where: signal, Assurance: AssuranceGatingRisk},
			RuleAssuranceMismatch, "skipped with a warning"},
		{"enforcement on a control that reads a detector", Policy{ID: "p", Authority: contract.AuthorityConstraint, Where: signal, Assurance: AssuranceEnforcement},
			RuleAssuranceMismatch, "signal.detector.probe"},
		{"gating risk on a deterministic control", Policy{ID: "p", Authority: contract.AuthorityConstraint, Where: deterministic, Assurance: AssuranceGatingRisk},
			RuleAssuranceMismatch, "reads nothing from the signal namespace"},
		{"a class on a permission", Policy{ID: "p", Authority: contract.AuthorityPermission, Where: deterministic, Assurance: AssuranceEnforcement},
			RuleAssuranceOnPermission, "a permission only widens"},
		{"a class nobody declared", Policy{ID: "p", Authority: contract.AuthorityConstraint, Where: deterministic, Assurance: AssuranceClass("strong")},
			RuleAssuranceUnknown, `"strong"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateAssurance(tc.policy)
			if len(errs) != 1 || errs[0].Rule != tc.rule || !strings.Contains(errs[0].Detail, tc.detail) {
				t.Fatalf("validateAssurance = %v, want one %s naming %q", errs, tc.rule, tc.detail)
			}
		})
	}
	// THE CONTROL: every class that matches its shape is accepted.
	for _, p := range []Policy{
		{ID: "a", Authority: contract.AuthorityConstraint, Where: signal, Assurance: AssuranceGatingRisk},
		{ID: "b", Authority: contract.AuthorityConstraint, Where: deterministic, Assurance: AssuranceEnforcement},
		{ID: "c", Authority: contract.AuthorityInspection, Where: signal, Assurance: AssuranceAdvisory},
	} {
		if errs := validateAssurance(p); len(errs) != 0 {
			t.Fatalf("a matching declaration on %s was refused: %v", p.ID, errs)
		}
	}
}

// TestTheShippedCorpusRefusesAnUndeclaredOrContradictedClass is the load-time
// rule: drop the class from one shipped control, or contradict it, and the
// corpus is refused rather than defaulted.
func TestTheShippedCorpusRefusesAnUndeclaredOrContradictedClass(t *testing.T) {
	shipped, err := SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireDeclaredAssurance(shipped); err != nil {
		t.Fatalf("the shipped system document is refused: %v", err)
	}
	template, err := SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireDeclaredAssurance(template); err != nil {
		t.Fatalf("the shipped organization template is refused: %v", err)
	}

	gating := -1
	for i, p := range shipped.Policies {
		if p.Assurance == AssuranceGatingRisk {
			gating = i
			break
		}
	}
	if gating < 0 {
		t.Fatal("the shipped corpus has no gating_risk control, so the cases below would prove nothing")
	}
	copyWith := func(edit func(*Policy)) *Document {
		d := *shipped
		d.Policies = append([]Policy(nil), shipped.Policies...)
		edit(&d.Policies[gating])
		return &d
	}
	id := shipped.Policies[gating].ID

	undeclared := copyWith(func(p *Policy) { p.Assurance = "" })
	if err := RequireDeclaredAssurance(undeclared); err == nil || !strings.Contains(err.Error(), id) || !strings.Contains(err.Error(), "declares no assurance class") {
		t.Fatalf("a shipped control with its class dropped returned %v; want a refusal naming %s", err, id)
	}
	contradicted := copyWith(func(p *Policy) { p.Assurance = AssuranceAdvisory })
	if err := RequireDeclaredAssurance(contradicted); err == nil || !strings.Contains(err.Error(), RuleAssuranceMismatch) {
		t.Fatalf("a gating control declared advisory returned %v; want %s", err, RuleAssuranceMismatch)
	}
}

// TestTheDeclaredAssuranceClassIsWhatTheCombinerDoes is the evidence that the
// shipped classes are right, and it does not call DeriveAssurance.
//
// Every shipped control is handed to the real combiner as UNKNOWN beside a
// matched permission, and the decision is read: a control declared advisory
// must leave the request permitted, and a control declared enforcement or
// gating_risk must make it indeterminate - fail closed - for the reason its
// authority names. A declaration that agreed with the derivation and disagreed
// with the engine would fail here, which is the shape a re-implementation that
// agrees with itself cannot catch.
func TestTheDeclaredAssuranceClassIsWhatTheCombinerDoes(t *testing.T) {
	shipped, err := SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	template, err := SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	principal := contract.MustParseID(contract.KindPrincipal, "User::realm_ws:alice")
	now := time.Now()
	req := &contract.Request{
		RequestID:    "r-assurance",
		Organization: contract.MustParseID(contract.KindOrganization, "Organization::org_acme"),
		Principal:    principal,
		Action:       contract.MustParseID(contract.KindAction, "Action::ticket.read"),
		Resource:     contract.MustParseID(contract.KindResource, "Ticket::conn:T-1"),
		Context:      contract.Context{ActorChain: []contract.Actor{{ID: principal, Attributes: contract.AttributeSet{}}}},
		Snapshot:     contract.Snapshot{SchemaVersion: contract.SchemaVersion, PolicyBundle: "sha256:aa"},
		Attributes:   contract.AttributeSet{},
		EvaluatedAt:  now,
	}

	checked := map[AssuranceClass]int{}
	for _, doc := range []*Document{shipped, template} {
		for _, p := range doc.Policies {
			if p.Assurance == "" {
				continue
			}
			paths := p.ReferencedPaths()
			cause := "args.unresolved"
			if len(paths) > 0 {
				cause = paths[0]
			}
			dec, err := Combine(CombineInput{
				Request: req,
				Outcomes: []PolicyOutcome{
					{PolicyID: "grant", Authority: contract.AuthorityPermission, Root: RootOrganization, Verdict: VerdictMatch},
					{PolicyID: p.ID, Authority: p.Authority, Root: p.Root, Verdict: VerdictUnknown,
						Causes: []UnknownCause{{Path: cause, Reason: contract.ReasonNotSupplied}}},
				},
				Meta: map[string]PolicyMeta{
					"grant": {ID: "grant", Authority: contract.AuthorityPermission, Root: RootOrganization},
					p.ID: {ID: p.ID, Authority: p.Authority, Root: p.Root, Obligations: p.Obligations,
						Mandatory: p.Mandatory, PierceableBy: p.PierceableBy},
				},
				PEP:            &contract.PEPProfile{ID: "pep"},
				ApprovalExpiry: now.Add(time.Hour),
				DecisionID:     "d-assurance",
			})
			if err != nil {
				t.Fatalf("%s: the combiner refused the input: %v", p.ID, err)
			}
			failsClosed := dec.Authorization == contract.AuthzIndeterminate &&
				(dec.Reason == contract.ReasonUnknownConstraint || dec.Reason == contract.ReasonUnknownRequirement)
			failsOpen := dec.Authorization == contract.AuthzPermit
			switch p.Assurance {
			case AssuranceAdvisory:
				if !failsOpen {
					t.Errorf("%s is declared advisory and the combiner answered %s/%s when it could not be evaluated; an advisory control cannot deny",
						p.ID, dec.Authorization, dec.Reason)
				}
			case AssuranceEnforcement, AssuranceGatingRisk:
				if !failsClosed {
					t.Errorf("%s is declared %s and the combiner answered %s/%s when it could not be evaluated; that class denies on error",
						p.ID, p.Assurance, dec.Authorization, dec.Reason)
				}
			default:
				t.Errorf("%s declares class %q", p.ID, p.Assurance)
			}
			checked[p.Assurance]++
		}
	}
	if checked[AssuranceAdvisory] == 0 || checked[AssuranceGatingRisk] == 0 {
		t.Fatalf("checked %v; both a failing-open and a failing-closed class must be exercised for this to mean anything", checked)
	}
	t.Logf("shipped controls driven through the combiner as unknown, by declared class: %v", checked)
}
