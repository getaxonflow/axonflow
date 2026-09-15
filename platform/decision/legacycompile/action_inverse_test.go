// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// sharedShape is the action each collapsed action reads back as: the two pairs
// that compile to one shape answer the first of the pair.
var sharedShape = map[LegacyAction]LegacyAction{ActionDeny: ActionBlock, ActionLogOnly: ActionLog}

func readsBackAs(act LegacyAction) LegacyAction {
	if first, shared := sharedShape[act]; shared {
		return first
	}
	return act
}

// TestLegacyActionOfInvertsEveryActionMapping compiles every known action
// through the one mapping it has (ActionPolicy, or ApprovalPolicy for
// require_approval) and reads it back, with the category and severity the
// shape records.
func TestLegacyActionOfInvertsEveryActionMapping(t *testing.T) {
	for _, act := range KnownActions() {
		base := pdp.Policy{ID: "corpus:static_policies:round__trip", Actions: pdp.ActionSelector{Any: true}}
		var p *pdp.Policy
		if act == ActionRequireApproval {
			p = ApprovalPolicy(base, ApprovalPool{Quorum: 1, Eligible: []string{"Principal::approver"}})
		} else {
			compiled, reasons := ActionPolicy(base, act, "pii-roundtrip", "high", DefaultContentTarget, PlaneDecide)
			if compiled == nil {
				t.Fatalf("%s does not compile through ActionPolicy: %v", act, reasons)
			}
			p = compiled
		}
		want := readsBackAs(act)
		got, category, severity, ok := LegacyActionOf(*p)
		if !ok || got != want {
			t.Errorf("%s reads back as %q (ok=%v), want %q", act, got, ok, want)
			continue
		}
		wantCategory, wantSeverity := "", ""
		switch want {
		case ActionWarn, ActionLog:
			wantCategory, wantSeverity = "pii-roundtrip", "high"
		case ActionAllow:
			wantCategory = "pii-roundtrip"
		}
		if category != wantCategory || severity != wantSeverity {
			t.Errorf("%s reads back category %q severity %q, want %q and %q", act, category, severity, wantCategory, wantSeverity)
		}
	}
}

// TestLegacyActionOfNamesNoActionForAShapeNoMappingProduces holds the inverse to
// refusing every shape the two mappings never produce, so an authored policy is
// never reported as a legacy action it does not enforce.
func TestLegacyActionOfNamesNoActionForAShapeNoMappingProduces(t *testing.T) {
	notify := contract.Obligation{Type: contract.ObNotification, Params: map[string]string{"category": "c", "severity": "s"}}
	for name, p := range map[string]pdp.Policy{
		"a permission": {ID: "p", Authority: contract.AuthorityPermission},
		"a constraint carrying an obligation": {ID: "c", Authority: contract.AuthorityConstraint,
			Obligations: []contract.Obligation{notify}},
		"a requirement carrying two obligations": {ID: "two", Authority: contract.AuthorityRequirement,
			Obligations: []contract.Obligation{notify, notify}},
		"a requirement carrying none": {ID: "none", Authority: contract.AuthorityRequirement},
		"a redaction that is not mandatory": {ID: "r", Authority: contract.AuthorityRequirement,
			Obligations: []contract.Obligation{{Type: contract.ObFieldRedact}}},
		"an approval challenge that is not mandatory": {ID: "a", Authority: contract.AuthorityRequirement,
			Obligations: []contract.Obligation{{Type: contract.ObApprovalChallenge}}},
		"an inspection that observed something other than allow": {ID: "i", Authority: contract.AuthorityInspection,
			Obligations: []contract.Obligation{{Type: contract.ObImmutableAudit, Params: map[string]string{"observed": "block"}}}},
		"an audit that records an observation on a requirement": {ID: "o", Authority: contract.AuthorityRequirement,
			Obligations: []contract.Obligation{{Type: contract.ObImmutableAudit, Params: map[string]string{"observed": "allow"}}}},
	} {
		if act, _, _, ok := LegacyActionOf(p); ok {
			t.Errorf("%s reads as the legacy action %q; no mapping produces that shape", name, act)
		}
	}
}

// TestLegacyActionOfAgreesWithEveryShippedVariant reads every per-scope variant
// of the shipped corpus back through LegacyActionOf. A variant is a control whose
// legacy action differs by enforcement scope, and its identifier names the action
// it was compiled with (CorpusVariantIDFor), so the corpus itself is the answer
// key. It refuses to pass on a corpus with no variant.
func TestLegacyActionOfAgreesWithEveryShippedVariant(t *testing.T) {
	sys, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, p := range sys.Policies {
		_, variant, isCorpus := CorpusControlOf(p.ID)
		if !isCorpus || variant == "" {
			continue
		}
		checked++
		want := readsBackAs(LegacyAction(variant))
		if got, _, _, ok := LegacyActionOf(p); !ok || got != want {
			t.Errorf("%s reads back as %q (ok=%v); its identifier names %q", p.ID, got, ok, variant)
		}
	}
	if checked == 0 {
		t.Fatal("the shipped corpus carries no per-scope variant, so this test would prove nothing")
	}
	t.Logf("%d shipped per-scope variants read back to the action their identifier names", checked)
}

// TestLegacyActionOfReadsEveryShippedStaticControl reads every control the
// shipped corpus compiled from a static_policies row. Each was compiled through
// ActionPolicy or ApprovalPolicy, so each must read back to some legacy action;
// one that does not is a shape the inverse has not learned.
func TestLegacyActionOfReadsEveryShippedStaticControl(t *testing.T) {
	sys, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, p := range sys.Policies {
		if !strings.HasPrefix(p.ID, "corpus:static_policies:") {
			continue
		}
		checked++
		if _, _, _, ok := LegacyActionOf(p); !ok {
			t.Errorf("%s (%s, %d obligation(s), mandatory=%v) reads as no legacy action", p.ID, p.Authority, len(p.Obligations), p.Mandatory)
		}
	}
	if checked == 0 {
		t.Fatal("the shipped corpus carries no static control, so this test would prove nothing")
	}
	t.Logf("%d shipped static controls read back to a legacy action", checked)
}
