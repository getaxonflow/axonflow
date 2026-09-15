// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/legacycompile"
)

// THE DRAFT IMPORT SEES A TEMPLATE CONTROL SPLIT BY DISCHARGE AS ITS TWO IDS (#4131).
//
// A template redaction ships as one policy per action, each bound to the scopes
// that can or cannot carry a redaction out. The import works by CONTROL, so a
// legacy override naming the template row is judged on the control and never
// on a variant id, and the draft it writes carries the shipped template whole,
// so the split control arrives there as both of its per-scope ids - the shape a
// system split already has.
func TestTheImportDraftCarriesATemplateControlSplitByDischargeUnderBothIDs(t *testing.T) {
	const row = "pii_ssn_detection"
	control := legacycompile.CorpusPolicyIDFor("static_policies", row)
	redactID := legacycompile.CorpusVariantIDFor("static_policies", row, "redact")
	warnID := legacycompile.CorpusVariantIDFor("static_policies", row, "warn")

	rec, err := buildImportRecord([]importCandidate{
		withAction(importRow("o-union", "static_policies", "sys_sqli_union_select"), "block"),
		withAction(importRow("o-ssn", "static_policies", row), "block"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// The template row's override names no SYSTEM control, so it is skipped with
	// the code every template row's override gets, and it names the control.
	var ssn *importSkip
	for i := range rec.Skipped {
		if rec.Skipped[i].OverrideID == "o-ssn" {
			ssn = &rec.Skipped[i]
		}
	}
	if ssn == nil {
		t.Fatalf("the override on %s was neither carried nor skipped: %+v", row, rec.Skipped)
	}
	if ssn.Code != "SYSTEM_CONTROL_UNKNOWN" || ssn.Control != control {
		t.Fatalf("the override on %s was skipped as %+v; want SYSTEM_CONTROL_UNKNOWN naming the control %s, never a per-scope id", row, *ssn, control)
	}

	// The draft carries the template, so the split control is there as both ids
	// and not as the unsplit one.
	var doc authoring.Document
	if err := json.Unmarshal(rec.Draft, &doc); err != nil {
		t.Fatalf("the draft does not parse: %v", err)
	}
	ids := map[string]bool{}
	for _, p := range doc.Policy.Policies {
		ids[p.ID] = true
	}
	if !ids[redactID] || !ids[warnID] || ids[control] {
		t.Fatalf("the draft carries %s=%v, %s=%v and the unsplit %s=%v; want both per-scope ids and not the unsplit one",
			redactID, ids[redactID], warnID, ids[warnID], control, ids[control])
	}
}
