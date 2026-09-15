// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// Two shipped system controls: a static control the corpus split into
// per-scope variants, and a dynamic control.
const (
	sysStaticControl  = "corpus:static_policies:sys__admin__audit__log"
	sysDynamicControl = "corpus:dynamic_policies:sys__dyn__anomalous__access"
)

func sysDisabled(control string) SystemControlEntry {
	off := false
	return SystemControlEntry{Control: control, Enabled: &off}
}

func sysActioned(control string, a legacycompile.LegacyAction) SystemControlEntry {
	return SystemControlEntry{Control: control, Action: a}
}

// THE CONTROL IDENTIFIER IS THE ONE THE SHIPPED POSTURE TABLE LISTS. The set a
// system_controls entry may name is derived from the corpus through
// legacycompile.CorpusControlOf; the posture table (pdp/shipped_posture.json) is
// the page an operator reads it from. The two must be the same set, or the
// documented way to name a control would name one the validator refuses.
func TestTheShippedSystemControlsAreThePostureTablesRows(t *testing.T) {
	shipped, err := shippedSystemControls()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../pdp/shipped_posture.json")
	if err != nil {
		t.Fatal(err)
	}
	var posture struct {
		System []struct {
			Policies []struct {
				PolicyID string `json:"policy_id"`
			} `json:"policies"`
		} `json:"system"`
	}
	if err := json.Unmarshal(raw, &posture); err != nil {
		t.Fatal(err)
	}
	rows := map[string]bool{}
	for _, row := range posture.System {
		for _, p := range row.Policies {
			control, _, ok := legacycompile.CorpusControlOf(p.PolicyID)
			if !ok {
				t.Fatalf("the posture table lists %q, which is not a corpus identifier", p.PolicyID)
			}
			rows[control] = true
		}
	}
	if len(rows) != len(posture.System) {
		t.Fatalf("the posture table's %d system rows name %d controls; each row is one control", len(posture.System), len(rows))
	}
	if !reflect.DeepEqual(shipped, rows) {
		t.Fatalf("the validator admits %d controls and the posture table lists %d", len(shipped), len(rows))
	}
	if !shipped[sysStaticControl] || !shipped[sysDynamicControl] {
		t.Fatalf("PREMISE: %s and %s are shipped controls", sysStaticControl, sysDynamicControl)
	}
	if DynamicSystemControl(sysStaticControl) || !DynamicSystemControl(sysDynamicControl) {
		t.Fatalf("DynamicSystemControl misreads %s or %s", sysStaticControl, sysDynamicControl)
	}
}

func TestValidateSystemControls(t *testing.T) {
	org := func(entries ...SystemControlEntry) *Document {
		return &Document{Policy: pdp.Document{Root: pdp.RootOrganization}, SystemControls: entries}
	}
	on := true
	for _, tc := range []struct {
		name string
		doc  *Document
		want []string
	}{
		{"disabling a static control", org(sysDisabled(sysStaticControl)), nil},
		{"re-actioning a static control", org(sysActioned(sysStaticControl, legacycompile.ActionBlock)), nil},
		{"disabling a dynamic control", org(sysDisabled(sysDynamicControl)), nil},
		{"no section", org(), nil},
		{"enabled true", org(SystemControlEntry{Control: sysStaticControl, Enabled: &on}), []string{CodeSystemControlMalformed}},
		{"neither enabled nor action", org(SystemControlEntry{Control: sysStaticControl}), []string{CodeSystemControlMalformed}},
		{"an action nobody can assign", org(sysActioned(sysStaticControl, legacycompile.ActionAllow)), []string{CodeSystemControlMalformed}},
		{"re-actioning a dynamic control", org(sysActioned(sysDynamicControl, legacycompile.ActionLog)), []string{CodeSystemControlNotReactionable}},
		{"a control the corpus does not ship", org(sysDisabled("corpus:static_policies:sys__no__such__control")), []string{CodeSystemControlUnknown}},
		{"a template control, which the document carries directly", org(sysDisabled("corpus:static_policies:drop__table__prevention")), []string{CodeSystemControlUnknown}},
		{"a control named twice", org(sysDisabled(sysStaticControl), sysDisabled(sysStaticControl)), []string{CodeSystemControlDuplicate}},
		{"on the system root", &Document{Policy: pdp.Document{Root: pdp.RootSystem}, SystemControls: []SystemControlEntry{sysDisabled(sysStaticControl)}},
			[]string{CodeSystemControlsOutsideOrganization}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateSystemControls(tc.doc).Codes(); !slices.Equal(got, tc.want) {
				t.Fatalf("codes %v; want %v", got, tc.want)
			}
		})
	}
}

func TestDiffReportsSystemControlChanges(t *testing.T) {
	cat := baseCatalog(t)
	const (
		restored   = "corpus:static_policies:sys__admin__config__table"
		tightened  = sysStaticControl
		leftOut    = "corpus:static_policies:sys__sqli__drop__table"
		newlyAdded = sysDynamicControl
	)
	shipped, err := shippedSystemControls()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{restored, tightened, leftOut, newlyAdded} {
		if !shipped[c] {
			t.Fatalf("PREMISE: %s is a shipped control", c)
		}
	}
	from := documentWith(t, cat, nil)
	from.SystemControls = []SystemControlEntry{sysDisabled(restored), sysActioned(tightened, legacycompile.ActionWarn), sysActioned(leftOut, legacycompile.ActionLog)}
	to := documentWith(t, cat, nil)
	to.SystemControls = []SystemControlEntry{sysActioned(tightened, legacycompile.ActionBlock), sysDisabled(leftOut), sysDisabled(newlyAdded)}

	diff, err := DiffDocuments(from, to)
	if err != nil {
		t.Fatal(err)
	}
	want := []SystemControlChange{
		{Control: newlyAdded, Kind: ChangeAdded, Effect: EffectWidening, After: "disabled"},
		{Control: tightened, Kind: ChangeModified, Effect: EffectNarrowing, Before: "action=warn", After: "action=block"},
		{Control: restored, Kind: ChangeRemoved, Effect: EffectNarrowing, Before: "disabled"},
		{Control: leftOut, Kind: ChangeModified, Effect: EffectWidening, Before: "action=log", After: "disabled"},
	}
	slices.SortFunc(want, func(a, b SystemControlChange) int { return strings.Compare(a.Control, b.Control) })
	if len(diff.SystemControls) != len(want) {
		t.Fatalf("system control changes %+v; want %d", diff.SystemControls, len(want))
	}
	for i, got := range diff.SystemControls {
		if got.Rationale == "" {
			t.Fatalf("%s: a change with no rationale", got.Control)
		}
		got.Rationale = ""
		if got != want[i] {
			t.Fatalf("change %d is %+v; want %+v", i, got, want[i])
		}
	}
	if diff.Empty() || diff.Effect != EffectMixed {
		t.Fatalf("empty %v effect %s; a section that widens and narrows is a mixed, non-empty change", diff.Empty(), diff.Effect)
	}

	same, err := DiffDocuments(to, to)
	if err != nil {
		t.Fatal(err)
	}
	if !same.Empty() || same.SystemControls != nil {
		t.Fatalf("an unchanged section reported %+v", same.SystemControls)
	}
}

// A DOCUMENT THAT CONTROLS NOTHING RENDERS EXACTLY AS BEFORE, so no published
// artifact's digest moves and no api_version bump is owed; one that controls
// something round-trips through the wire boundary, the published schema
// included.
func TestTheSystemControlsSectionIsAbsentUnlessUsedAndRoundTrips(t *testing.T) {
	d := baseDocument(t)
	for _, section := range [][]SystemControlEntry{nil, {}} {
		d.SystemControls = section
		raw, err := Render(d)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "system_controls") {
			t.Fatalf("a document controlling nothing (%#v) renders a system_controls member: %s", section, raw)
		}
	}

	d.SystemControls = []SystemControlEntry{sysDisabled(sysDynamicControl), sysActioned(sysStaticControl, legacycompile.ActionRedact)}
	raw, err := Render(d)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(raw)
	if err != nil {
		t.Fatalf("a document with a valid system_controls section does not pass the wire boundary: %v", err)
	}
	if !reflect.DeepEqual(back.SystemControls, d.SystemControls) {
		t.Fatalf("the section round-trips as %+v; want %+v", back.SystemControls, d.SystemControls)
	}
}
