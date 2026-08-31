package agent

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

const postureLeverTablePath = "../decision/legacycompile/legacy_posture_levers.tsv"

// TestPostureLeverTableDescribesBuildActionOverrides pins the ADR-065 shadow
// harness's model of the detection-posture lever to the map this function
// actually builds.
//
// # Why it matters to the migration specifically
//
// BuildActionOverrides decides which categories the deployment posture is
// allowed to displace, and the shadow diff attributes a displaced action to
// the posture rather than to the compiler. A category silently added to or
// removed from this map changes which rows the posture reaches, and the diff
// would then report a difference the migration tooling caused as one the
// substrate had.
//
// The gap the map already carries is part of the pin, not an oversight to fix
// here: HighRiskAction has no static category to displace and DangerousQuery
// Action is a legacy string category the gateway filters never evaluate, so
// neither appears. Both are recorded as known limitations on the compilation
// report; the pin is what stops one of them quietly appearing.
func TestPostureLeverTableDescribesBuildActionOverrides(t *testing.T) {
	rows := readLeverTSV(t, postureLeverTablePath)
	if len(rows) == 0 {
		t.Fatalf("%s contains no rows", postureLeverTablePath)
	}

	// Each lever gets a DISTINCT action, so the resulting map says which lever
	// reached which category. A config with one action everywhere would prove
	// only that some lever did.
	cfg := &ModeDetectionConfig{
		Enabled:                true,
		PIIAction:              DetectionActionRedact,
		SQLIAction:             DetectionActionBlock,
		SensitiveDataAction:    DetectionActionWarn,
		DangerousCommandAction: DetectionActionLog,
		DangerousQueryAction:   DetectionActionBlock,
	}
	byAction := map[sharedpolicy.Action]string{
		sharedpolicy.ActionRedact: "PII_ACTION",
		sharedpolicy.ActionBlock:  "SQLI_ACTION",
		sharedpolicy.ActionWarn:   "SENSITIVE_DATA_ACTION",
		sharedpolicy.ActionLog:    "DANGEROUS_COMMAND_ACTION",
	}
	overrides := cfg.BuildActionOverrides()

	got := map[string]string{}
	for cat, act := range overrides {
		lever, ok := byAction[act]
		if !ok {
			t.Fatalf("category %q was mapped to action %q, which no lever in this fixture produces; "+
				"BuildActionOverrides has gained a source the pin cannot attribute", cat, act)
		}
		got[string(cat)] = lever
	}

	want := map[string]string{}
	for _, r := range rows {
		if r["posture_lever"] == "-" {
			continue
		}
		want[r["category"]] = r["posture_lever"]
	}

	for cat, lever := range want {
		if got[cat] != lever {
			t.Fatalf("%s says category %q is displaced by %q; BuildActionOverrides maps it to %q",
				postureLeverTablePath, cat, lever, orNone(got[cat]))
		}
	}
	for cat, lever := range got {
		if want[cat] != lever {
			t.Fatalf("BuildActionOverrides maps category %q to lever %q, which %s does not record; "+
				"the shadow diff would attribute that displacement to the compiler instead of to the posture",
				cat, lever, postureLeverTablePath)
		}
	}

	// The negative half: the table must also record the categories NO lever
	// reaches, and at least one of them must exist. A table listing only the
	// levered categories would be silent about exactly the population whose
	// stored action is what runs.
	unlevered := 0
	for _, r := range rows {
		if r["posture_lever"] != "-" {
			continue
		}
		unlevered++
		if _, displaced := overrides[sharedpolicy.PolicyCategory(r["category"])]; displaced {
			t.Fatalf("%s records category %q as reached by no lever, but BuildActionOverrides displaces it",
				postureLeverTablePath, r["category"])
		}
	}
	if unlevered == 0 {
		t.Fatalf("%s records no unlevered category, so the negative direction asserted nothing", postureLeverTablePath)
	}

	// COMPLETENESS against the enum, in both directions. Without the first,
	// a category added to the enum with no lever - which is exactly the
	// unlevered population this table exists to record - goes unpinned.
	// Without the second, a misspelled category sits here forever AND
	// inflates the unlevered count that the anti-vacuity check above reads.
	const unregisteredSentinel = "an-unregistered-category"
	present := map[string]bool{}
	for _, r := range rows {
		present[r["category"]] = true
	}
	for _, c := range sharedpolicy.AllPolicyCategories() {
		if !present[string(c)] {
			t.Fatalf("%s has no row for the declared category %q; a category with no lever is a fact this table must record, not omit",
				postureLeverTablePath, c)
		}
	}
	declared := map[string]bool{unregisteredSentinel: true}
	for _, c := range sharedpolicy.AllPolicyCategories() {
		declared[string(c)] = true
	}
	for c := range present {
		if !declared[c] {
			t.Fatalf("%s carries category %q, which is not a declared category and not the %q sentinel; it pins nothing and inflates the unlevered count",
				postureLeverTablePath, c, unregisteredSentinel)
		}
	}
	t.Logf("pinned %d levered and %d unlevered categories", len(want), unlevered)
}

func orNone(s string) string {
	if s == "" {
		return "no lever"
	}
	return s
}

func readLeverTSV(t *testing.T, path string) []map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatalf("%s is empty", path)
	}
	header := strings.Split(sc.Text(), "\t")
	if len(header) != 2 || header[0] != "category" || header[1] != "posture_lever" {
		t.Fatalf("%s header is %v, want [category posture_lever]", path, header)
	}
	var out []map[string]string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) != 2 {
			t.Fatalf("%s: row %q has %d fields, want 2", path, line, len(f))
		}
		out = append(out, map[string]string{"category": f[0], "posture_lever": f[1]})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return out
}
