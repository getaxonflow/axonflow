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

// TestPostureLeverTableAgrees is the same pin for the detection-posture lever.
// Its main-module half is
// platform/agent/legacy_posture_lever_table_test.go.
func TestPostureLeverTableAgrees(t *testing.T) {
	rows := readTSV(t, "legacy_posture_levers.tsv", []string{"category", "posture_lever"})
	if len(rows) == 0 {
		t.Fatal("legacy_posture_levers.tsv is empty")
	}
	levered, unlevered := 0, 0
	for i, r := range rows {
		want := undash(r["posture_lever"])
		got := PostureLeverFor(r["category"])
		if got != want {
			t.Fatalf("legacy_posture_levers.tsv line %d: PostureLeverFor(%q) = %q, table says %q",
				i+2, r["category"], got, want)
		}
		if want == "" {
			unlevered++
		} else {
			levered++
		}
	}
	if levered == 0 || unlevered == 0 {
		t.Fatalf("the table records %d levered and %d unlevered categories; both directions must appear or the pin only checks one", levered, unlevered)
	}

	// The lever must actually displace, and must not displace where no lever
	// applies. Without both, Posture.Apply could be a no-op and every posture
	// case in the shadow corpus would silently assert nothing.
	p := Posture{"PII_ACTION": ActionWarn}
	if got, did := p.Apply("pii-us", ActionBlock); !did || got != ActionWarn {
		t.Fatalf("PII_ACTION did not displace a pii-us block: got %q displaced=%t", got, did)
	}
	if got, did := p.Apply("compliance-gdpr", ActionBlock); did || got != ActionBlock {
		t.Fatalf("a category no lever reaches was displaced: got %q displaced=%t", got, did)
	}
	// An empty posture is "no lever configured", which is not the same as a
	// lever set to the stored action.
	if got, did := (Posture{}).Apply("pii-us", ActionBlock); did || got != ActionBlock {
		t.Fatalf("an unconfigured posture displaced an action: got %q displaced=%t", got, did)
	}
	t.Logf("pinned %d levered and %d unlevered categories", levered, unlevered)
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
