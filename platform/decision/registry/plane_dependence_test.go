// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"strings"
	"testing"
	"time"
)

// A CONTROL WHOSE CLASS DIFFERS BY PLANE MUST STAY TWO FACTS, NOT ONE (#3884)
//
// Since #3963 and #3968 no shipped algorithmic detector is plane-dependent:
// every static call site runs the validator, `validator_planes` equals `planes`
// on all 101 census rows, and `BarePlanes()` is empty for every shipped
// record. So every test that reads the SHIPPED census can no longer tell the
// per-plane derivation from one that ignores the column and reports a gate
// everywhere - both produce the same records.
//
// That is the collapse this file exists to catch. A derivation that copied
// `planes` onto `GatingPlanes` for an algorithmic row would pass every shipped
// test and, the day an evaluator stops consulting the validator again, report
// a checksum-gated detector as gated on the plane where the bare pattern
// decides. The census input is therefore SYNTHETIC here, parsed through the
// real census parser and projected through the real `RecordFor`, so the
// derivation is driven where it can disagree.

// planeDependentCensus is one algorithmic row validated on decide, half-gated
// on policy_test and bare on openai_compatible - synthetic, since no shipped
// plane is bare after #3963 - written in the census's own format so the parse
// is part of what is under test.
func planeDependentCensus(t *testing.T) CensusRow {
	t.Helper()
	content := strings.Join(detectorCensusHeader, "\t") + "\n" + strings.Join([]string{
		"synthetic_card", "Synthetic card", "pii-global", "system", "true",
		"algorithmic", "platform/shared/policy/validators.go::ValidateCreditCard", "redact", "high",
		"Signal", "field_redact", "-",
		"compiled", "-", "decide,policy_test,openai_compatible", "decide,policy_test(mixed)",
		"031_x.sql", "-",
	}, "\t") + "\n"
	rows, err := ParseDetectorCensus(content)
	if err != nil {
		t.Fatalf("the plane-dependent fixture does not parse, so nothing below is evidence: %v", err)
	}
	return rows[0]
}

// TestAPlaneDependentCensusRowProjectsToAPlaneDependentRecord is the DoD's
// "represented as differing, not collapsed", asserted per plane and naming the
// plane that disagrees.
func TestAPlaneDependentCensusRowProjectsToAPlaneDependentRecord(t *testing.T) {
	rec := RecordFor(planeDependentCensus(t))

	want := map[string]string{"decide": "gating", "policy_test": "mixed", "openai_compatible": "bare"}
	got := map[string]string{}
	for _, p := range rec.GatingPlanes {
		got[p] = "gating"
	}
	for _, p := range rec.MixedPlanes {
		got[p] = "mixed"
	}
	for _, p := range rec.BarePlanes() {
		got[p] = "bare"
	}
	for plane, class := range want {
		if got[plane] != class {
			t.Errorf("plane %q: the census says the implementation (%s) is %s there and the record says %q. "+
				"A record that reports one class for every plane imports a control that does not exist on this one",
				plane, rec.Impl, class, got[plane])
		}
	}
	if len(got) != len(want) {
		t.Errorf("the record classifies planes %v; the census row runs on exactly %v", got, want)
	}

	// And the refusal that depends on it, through a catalog, on each plane.
	c := NewCatalog(time.Now())
	mustRegister(t, c, rec)
	if f := c.CheckDetectorSelection(rec.ID, []string{"openai_compatible"}); !f.Has(CodeDetectorPlaneCannotGate) {
		t.Errorf("selecting openai_compatible, where the pattern decides alone, was not refused as bare: %v", f)
	}
	if f := c.CheckDetectorSelection(rec.ID, []string{"policy_test"}); !f.Has(CodeDetectorPlanePartiallyGates) {
		t.Errorf("selecting policy_test, which one phase gates and one does not, was not refused as mixed: %v", f)
	}
	if f := c.CheckDetectorSelection(rec.ID, []string{"decide"}); f.Blocking() {
		t.Errorf("selecting decide, where the implementation gates, was refused: %v", f.Err())
	}
}

// TestAPatternRowIsNotMadePlaneDependentByTheValidatorColumn is the control on
// the other side of the same derivation. The census's validator column is a
// property of the PLANE; a pattern row gates everywhere it runs. A derivation
// that read the column for every class would report this row bare on
// openai_compatible, which the test above cannot see.
func TestAPatternRowIsNotMadePlaneDependentByTheValidatorColumn(t *testing.T) {
	row := planeDependentCensus(t)
	row.Class = DetectorClassPattern
	row.ImplSite = "re2:sha256:0123456789ab"
	rec := RecordFor(row)
	if bare := rec.BarePlanes(); len(bare) > 0 {
		t.Errorf("a pattern row is reported bare on %v; the pattern is what every engine runs, so it gates on every plane it runs on", bare)
	}
	if len(rec.MixedPlanes) > 0 {
		t.Errorf("a pattern row is reported mixed on %v", rec.MixedPlanes)
	}
}
