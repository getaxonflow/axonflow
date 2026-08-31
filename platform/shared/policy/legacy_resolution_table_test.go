package policy

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resolutionTablePath is the artifact this test and the ADR-065 migration
// compiler both read.
const resolutionTablePath = "../../decision/legacycompile/legacy_resolution.tsv"

// TestLegacyResolutionTableDescribesGetActionForPhase pins the ADR-065 shadow
// harness's model of THIS function to the function itself.
//
// # Why the pin exists
//
// platform/decision/legacycompile reimplements GetActionForPhase, because the
// decision module is a separate Go module with its own pinned OPA and cannot
// import this one. That reimplementation is the LEGACY side of a differential
// harness, and a legacy side that is merely believed to match the legacy
// engine is worth nothing: the whole exercise assumes it IS the legacy engine.
//
// # Why a checked-in table rather than a shared function
//
// One artifact, two independent readers, one in each module. This test proves
// the table describes the real GetActionForPhase, exhaustively over every
// declared category, every severity, both phases and every stored-action
// state. TestResolutionTableIsExhaustiveAndAgrees, in the decision module,
// proves the compiler's model reproduces the same table. Neither can drift
// silently, and no cross-module dependency is created to achieve it.
//
// If this test fails, the resolution semantics changed. Regenerate the table
// only after deciding whether the shadow diffs already taken are still valid,
// because they were measured against the old one.
func TestLegacyResolutionTableDescribesGetActionForPhase(t *testing.T) {
	rows := readTSV(t, resolutionTablePath, []string{"category", "severity", "phase", "stored_action", "resolved_action"})
	if len(rows) == 0 {
		t.Fatalf("%s contains no rows; an empty table would let this test pass while asserting nothing", resolutionTablePath)
	}

	seenCategories := map[string]bool{}
	for i, r := range rows {
		category := r["category"]
		severity := undash(r["severity"])
		phase := Phase(r["phase"])
		seenCategories[category] = true

		p := &CompiledPolicy{
			Category: PolicyCategory(category),
			Severity: Severity(severity),
		}
		switch r["stored_action"] {
		case "NULL", "EMPTY":
			// A NULL column scans into sql.NullString and compilePolicy leaves
			// the Action zero, so NULL and an empty string are the same value
			// by the time GetActionForPhase sees them. The table carries both
			// spellings deliberately: they must resolve identically, and a
			// change that made them differ would be invisible with only one.
		default:
			if phase == PhaseRequest {
				p.ActionRequest = Action(r["stored_action"])
			} else {
				p.ActionResponse = Action(r["stored_action"])
			}
		}

		got := string(p.GetActionForPhase(phase))
		if got != r["resolved_action"] {
			t.Fatalf("%s line %d: GetActionForPhase(category=%q severity=%q phase=%q stored=%q) = %q, table says %q",
				resolutionTablePath, i+2, category, severity, phase, r["stored_action"], got, r["resolved_action"])
		}
	}

	// Anti-vacuity, derived rather than calibrated: the table must cover every
	// category constant this package declares. A table that had lost half its
	// rows would still agree with the function on the rows it kept.
	for _, c := range AllPolicyCategories() {
		if !seenCategories[string(c)] {
			t.Fatalf("%s has no rows for the declared category %q; the shadow harness would model it from an unpinned code path", resolutionTablePath, c)
		}
	}
	// And the other direction, which is the one that catches a TYPO. A
	// misspelled category agrees with GetActionForPhase on every row - the
	// fallback does not care what the string is - so it sits in the table
	// forever pinning nothing, and a reader counting categories is misled.
	//
	// One deliberate exception, named rather than pattern-matched: the table
	// pins the fallback for a category the enum does NOT declare, which is
	// reachable because static_policies.category is a VARCHAR with no CHECK.
	const unregisteredSentinel = "an-unregistered-category"
	declared := map[string]bool{unregisteredSentinel: true}
	for _, c := range AllPolicyCategories() {
		declared[string(c)] = true
	}
	for c := range seenCategories {
		if !declared[c] {
			t.Fatalf("%s carries category %q, which this package does not declare and which is not the %q sentinel; a misspelled category pins nothing",
				resolutionTablePath, c, unregisteredSentinel)
		}
	}
	if !seenCategories[unregisteredSentinel] {
		t.Fatalf("%s no longer carries the %q sentinel, so the fallback for an undeclared category is unpinned",
			resolutionTablePath, unregisteredSentinel)
	}
	t.Logf("pinned %d resolution rows across %d categories", len(rows), len(seenCategories))
}

// TestLegacyResolutionTableCoversTheSourceEnum is the other half of the
// completeness check: every category constant declared above must actually
// exist in this package, so the list cannot rot into naming things that were
// renamed or removed.
func TestLegacyResolutionTableCoversTheSourceEnum(t *testing.T) {
	src, err := os.ReadFile("types.go")
	if err != nil {
		t.Fatalf("reading types.go: %v", err)
	}
	text := string(src)
	for _, c := range AllPolicyCategories() {
		if !strings.Contains(text, `PolicyCategory = "`+string(c)+`"`) {
			t.Fatalf("AllPolicyCategories names %q, which types.go does not declare", c)
		}
	}
	// And the reverse: every `PolicyCategory = "..."` in types.go must appear
	// in the list. This is the direction that catches a NEW category, which is
	// the one that would otherwise be modelled by an unpinned code path.
	declared := map[string]bool{}
	for _, c := range AllPolicyCategories() {
		declared[string(c)] = true
	}
	for _, line := range strings.Split(text, "\n") {
		i := strings.Index(line, `PolicyCategory = "`)
		if i < 0 {
			continue
		}
		rest := line[i+len(`PolicyCategory = "`):]
		j := strings.Index(rest, `"`)
		if j < 0 {
			continue
		}
		if !declared[rest[:j]] {
			t.Fatalf("types.go declares category %q, which is missing from AllPolicyCategories and therefore from both pinned migration tables", rest[:j])
		}
	}
}

func readTSV(t *testing.T, path string, wantHeader []string) []map[string]string {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
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
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(strings.TrimRight(line, "\r"), "\t")
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

// TestGetActionForPhaseBothFallsThroughToTheFallback pins a latent branch the
// resolution table cannot carry: GetActionForPhase called with PhaseBoth.
//
// "both" is a STORED phase value (the column's default, migration core/039),
// not an evaluation phase - every production caller passes PhaseRequest or
// PhaseResponse - so the function's switch has no arm for it and the call
// falls through to the category/severity fallback, IGNORING both stored
// action columns even when both are set. That is why legacy_resolution.tsv
// carries only request and response rows: the table pins what production can
// reach, and this test pins the fallthrough so the first caller to pass a
// stored phase as an evaluation phase changes a TESTED answer, not a silent
// one. The row deliberately stores BOTH action columns, which the table's
// per-phase rows never exercise together.
func TestGetActionForPhaseBothFallsThroughToTheFallback(t *testing.T) {
	p := &CompiledPolicy{
		Category: CategoryAdminAccess, Severity: SeverityHigh,
		ActionRequest: ActionBlock, ActionResponse: ActionRedact,
	}
	// admin-access falls back to warn - an action NEITHER stored column
	// carries, so this cannot pass by coincidence with either of them.
	if got := p.GetActionForPhase(PhaseBoth); got != ActionWarn {
		t.Fatalf("GetActionForPhase(PhaseBoth) = %q, want the category fallback %q: the switch has no arm for a stored "+
			"phase used as an evaluation phase, and both stored action columns are ignored on that path", got, ActionWarn)
	}
	// The same both-columns row resolves each REAL evaluation phase from its
	// own column - the property that makes the fallthrough above a fact about
	// PhaseBoth rather than about this row.
	if got := p.GetActionForPhase(PhaseRequest); got != ActionBlock {
		t.Fatalf("GetActionForPhase(PhaseRequest) = %q, want the stored action_request %q", got, ActionBlock)
	}
	if got := p.GetActionForPhase(PhaseResponse); got != ActionRedact {
		t.Fatalf("GetActionForPhase(PhaseResponse) = %q, want the stored action_response %q", got, ActionRedact)
	}
}
