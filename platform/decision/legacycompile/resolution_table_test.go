// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// TestResolutionTableIsExhaustiveAndAgrees is this module's half of the pin
// that binds the legacy model to the legacy engine.
//
// The other half lives in the MAIN module
// (platform/shared/policy/legacy_resolution_table_test.go) and proves the same
// table describes the real GetActionForPhase. One artifact, two independent
// readers, one per module, and no cross-module import - which matters because
// the decision module pins its own OPA and is deliberately standalone.
//
// If this fails, the model and the table disagree. If the OTHER one fails, the
// table and the engine disagree. Both must pass for a shadow diff to mean
// anything at all, because a legacy side that is not the legacy engine makes
// every "match" an artefact.
func TestResolutionTableIsExhaustiveAndAgrees(t *testing.T) {
	rows := readTSV(t, "legacy_resolution.tsv", []string{"category", "severity", "phase", "stored_action", "resolved_action"})
	if len(rows) == 0 {
		t.Fatal("legacy_resolution.tsv is empty; an empty table would let this test pass while asserting nothing")
	}
	categories, severities, phases, storedStates := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}

	for i, r := range rows {
		category, severity := r["category"], undash(r["severity"])
		categories[category] = true
		severities[severity] = true
		phases[r["phase"]] = true
		storedStates[r["stored_action"]] = true

		var stored string
		switch r["stored_action"] {
		case "NULL", "EMPTY":
			// Both spellings of "no stored action". compilePolicy leaves the
			// Action zero for a NULL column, so the legacy engine cannot tell
			// them apart and they MUST resolve identically. The table carries
			// both rows so that a change making them differ fails here.
			stored = ""
		default:
			stored = r["stored_action"]
		}
		got := string(ResolveActionForPhase(category, severity, stored))
		if got != r["resolved_action"] {
			t.Fatalf("legacy_resolution.tsv line %d: ResolveActionForPhase(%q, %q, %q) = %q, table says %q",
				i+2, category, severity, stored, got, r["resolved_action"])
		}
	}

	// Anti-vacuity, derived from the table's own shape rather than from a
	// hand-picked floor: the table must vary every axis the resolution depends
	// on. A table pinned on one severity, or on one phase, would agree with
	// the model on everything it contained and say nothing about the rest.
	if len(phases) != 2 {
		t.Fatalf("the table covers %d phase(s); resolution reads a different column per phase, so both must appear", len(phases))
	}
	if !storedStates["NULL"] || !storedStates["EMPTY"] {
		t.Fatal("the table must carry both the NULL and the EMPTY stored-action spellings: the legacy code collapses them, and only two rows can show that")
	}
	if len(severities) < 2 {
		t.Fatal("the table covers fewer than two severities; the security-category fallback is severity-dependent")
	}
	if len(categories) < 10 {
		t.Fatalf("the table covers %d categories; the fallback branches on category family and a narrow table would not exercise them", len(categories))
	}
	t.Logf("agreed on %d rows across %d categories, %d severities, %d phases, %d stored-action states",
		len(rows), len(categories), len(severities), len(phases), len(storedStates))
}

// TestCategoryActionsApplyByCategory pins that an assigned action is looked up
// by the policy CATEGORY - the key EvalOptions.ActionOverrides carries - and by
// nothing else (#3961). It was keyed by environment-variable name while the
// decision shadow's observer (retired in v11) passed the engine's category-keyed
// map, so on that path no action was ever found. Without these assertions Apply
// could be a no-op and every override case would silently assert nothing.
func TestCategoryActionsApplyByCategory(t *testing.T) {
	c := CategoryActions{"pii-us": ActionWarn}
	if got, did := c.Apply("pii-us", ActionBlock); !did || got != ActionWarn {
		t.Fatalf("an action assigned to pii-us did not displace a pii-us block: got %q displaced=%t", got, did)
	}
	if got, did := c.Apply("pii-eu", ActionBlock); did || got != ActionBlock {
		t.Fatalf("an action assigned to pii-us displaced pii-eu: got %q displaced=%t", got, did)
	}
	// The retired lever-name key must not be read as a category.
	if got, did := (CategoryActions{"PII_ACTION": ActionWarn}).Apply("pii-us", ActionBlock); did || got != ActionBlock {
		t.Fatalf("a lever-name key displaced a category action: got %q displaced=%t", got, did)
	}
	// No action assigned is not the same as one assigned the stored action.
	if got, did := (CategoryActions{}).Apply("pii-us", ActionBlock); did || got != ActionBlock {
		t.Fatalf("empty category actions displaced an action: got %q displaced=%t", got, did)
	}
	if _, did := (CategoryActions{"pii-us": ActionBlock}).Apply("pii-us", ActionBlock); !did {
		t.Fatal("an action assigned equal to the stored one was not reported as a displacement; the audit trail must still show it")
	}
}

func readTSV(t *testing.T, path string, wantHeader []string) []map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	if !sc.Scan() {
		t.Fatalf("%s is empty", path)
	}
	header := strings.Split(sc.Text(), "\t")
	if len(header) != len(wantHeader) {
		t.Fatalf("%s header is %v, want %v", path, header, wantHeader)
	}
	for i, h := range wantHeader {
		if header[i] != h {
			t.Fatalf("%s column %d is %q, want %q", path, i, header[i], h)
		}
	}
	var out []map[string]string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != len(header) {
			t.Fatalf("%s: row %q has %d fields, want %d", path, line, len(fields), len(header))
		}
		row := map[string]string{}
		for i, h := range header {
			row[h] = fields[i]
		}
		out = append(out, row)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return out
}

func undash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}
