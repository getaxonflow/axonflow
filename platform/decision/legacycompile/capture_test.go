package legacycompile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// TestCapturedCorpusReconciles compiles a REAL capture from a fresh stack and
// reconciles the record count against SELECT count(*).
//
// It is the acceptance test for "no unsupported legacy policy is silently
// dropped or widened" on real data rather than on fixtures. Fixtures prove the
// compiler handles the shapes somebody thought of; a fresh stack's seeded
// policy set is the shape that actually exists.
//
// It skips without a capture, because CI has no database in this module and a
// test that fabricated one would be testing the fabrication. Produce a capture
// with scripts/legacy-policy-capture.sh and point AXONFLOW_LEGACY_CAPTURE_DIR
// at it. The skip is LOUD about what was not verified, so a green run cannot
// be read as this test having passed.
func TestCapturedCorpusReconciles(t *testing.T) {
	dir := os.Getenv("AXONFLOW_LEGACY_CAPTURE_DIR")
	if dir == "" {
		t.Skip("no AXONFLOW_LEGACY_CAPTURE_DIR: the count reconciliation against a live SELECT count(*) was NOT run. " +
			"Produce a capture with scripts/legacy-policy-capture.sh and set the variable.")
	}

	owner := loadCapture(t, filepath.Join(dir, "capture-owner.json"))
	counts := loadCounts(t, filepath.Join(dir, "counts.json"))

	rep, err := Compile(owner, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if err := rep.Reconcile(counts); err != nil {
		t.Fatalf("reconciliation failed: %v", err)
	}

	byStatus := rep.CountsByStatus()
	byTable := rep.CountsByTable()
	t.Logf("captured %d row(s): %v", rep.InputRows, byTable)
	t.Logf("SELECT count(*): %v", counts)
	t.Logf("status: compiled=%d preserved_defect=%d uncompilable=%d",
		byStatus[StatusCompiled], byStatus[StatusPreservedDefect], byStatus[StatusUncompilable])
	byReason := rep.CountsByReason()
	var codes []ReasonCode
	for c := range byReason {
		codes = append(codes, c)
	}
	sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })
	for _, c := range codes {
		issue, isDefect := IsDefectReason(c)
		mark := ""
		if isDefect {
			mark = " (preserved legacy defect, " + issue + ")"
		}
		t.Logf("  %-45s %d row(s)%s", c, byReason[c], mark)
	}

	// Anti-vacuity. A capture that reconciled zero rows against zero rows
	// would pass this test having verified nothing, and it is exactly what a
	// broken capture produces.
	if rep.InputRows == 0 {
		t.Fatal("the capture contains no rows; a reconciliation of nothing against nothing is not evidence")
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	if total == 0 {
		t.Fatal("counts.json reports zero rows in every table; the capture did not read a migrated database")
	}

	// The app-role capture is compared against the owner capture, so rows the
	// RUNTIME cannot see under row-level security are named rather than left
	// to be discovered at cutover.
	appPath := filepath.Join(dir, "capture-approle.json")
	if _, err := os.Stat(appPath); err != nil {
		t.Fatal("no capture-approle.json: the row-level-security visibility comparison is not optional, " +
			"because a capture taken only as the owner describes rows enforcement may not be able to reach")
	}
	app := loadCapture(t, appPath)
	if len(app) == 0 {
		t.Fatal("the app-role capture is empty; a comparison against nothing reports every row as RLS-invisible or none, " +
			"depending on which way it is read, and neither is evidence")
	}
	visible := map[string]bool{}
	scopes := map[string]bool{}
	for _, r := range app {
		visible[r.Table+"|"+r.stringOr("policy_id", "")] = true
		scopes[r.OrgScope] = true
	}
	var invisible []string
	for _, r := range owner {
		k := r.Table + "|" + r.stringOr("policy_id", "")
		if !visible[k] {
			invisible = append(invisible, k)
		}
	}
	sort.Strings(invisible)
	t.Logf("rows visible to the owner but NOT to the app role under RLS: %d (across %d org scope(s))", len(invisible), len(scopes))
	for _, k := range invisible {
		t.Logf("  RLS-invisible: %s", k)
	}
	// Honesty about what this comparison can and cannot show. Under core/018's
	// `org_id = get_current_org_id()`, a capture whose scope loop is built from
	// the same table's DISTINCT org_id sees every row in exactly one pass, so
	// the invisible set is empty BY CONSTRUCTION on a single-scope substrate.
	// A zero here is therefore not a finding, and reporting it as one would be
	// the kind of green that means nothing.
	if len(scopes) <= 1 {
		t.Logf("NOTE: the capture carries a single org scope (%v), so the owner-versus-app-role comparison is "+
			"structurally unable to report a difference. It is UNEXERCISED, not clean.", keysOf(scopes))
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func loadCapture(t *testing.T, path string) []RawRow {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var rows []RawRow
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	return rows
}

func loadCounts(t *testing.T, path string) map[string]int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var counts map[string]int
	if err := json.Unmarshal(b, &counts); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	return counts
}
