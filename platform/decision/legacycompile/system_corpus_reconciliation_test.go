// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/registry"
)

// THE TWO MODELS, RECONCILED WITHOUT A DATABASE (#3884)
//
// The shipped controls live in two places until the legacy tables retire: the
// legacy tables a migration seeds, and the typed system document this binary
// activates. The guards below make "the same controls are in both" checkable on
// every pull request rather than asserted in a design document. The
// real-database half - the same reconciliation against a migrated database - is
// platform/agent/system_policy_count_realpg_test.go, and it runs on the tier
// that has Postgres.

// TestEveryShippedSystemControlExistsInBothModels fails when a shipped control
// exists in one model and not the other.
//
// THE LEGACY SIDE is every enabled system-tier row a migration seeds: the
// static rows from the detector census, which platform/shared/policy's census
// test holds to the forward-seeded migrations, and the dynamic rows parsed from
// migrations/core here, because no census covers dynamic_policies.
//
// THE MODEL SIDE is every system-root policy in the shipped document, keyed back
// to the row it came from, plus every row the corpus declares it does not
// represent. A row may be absent from the document only when it says so.
//
// IT RECONCILES ROWS, NOT POLICIES. A dynamic row compiles to one policy per
// obligation, so a row that lost one of its policies is still represented here.
// That removal is refused by TestTheSystemDocumentCarriesMorePoliciesThanRows,
// which holds every split row's policies to a complete set of siblings.
func TestEveryShippedSystemControlExistsInBothModels(t *testing.T) {
	c := shippedCorpusFromDisk(t)
	census, err := registry.ShippedCensus()
	if err != nil {
		t.Fatalf("ShippedCensus: %v", err)
	}

	legacy := map[string]string{} // "table/policy_id" -> where the row comes from
	for _, r := range census {
		if r.SystemTier() && r.Enabled {
			legacy["static_policies/"+r.PolicyID] = "census, seeded by " + r.SeedMigration
		}
	}
	dynamicSystem := 0
	for id, seed := range forwardSeededDynamicRows(t) {
		if seed.tier == "system" && seed.enabled {
			legacy["dynamic_policies/"+id] = "seeded by " + seed.file
			dynamicSystem++
		}
	}
	if dynamicSystem == 0 || len(legacy) == dynamicSystem {
		t.Fatalf("the legacy side found %d system-tier dynamic row(s) of %d system-tier rows; one half is empty, so "+
			"this reconciliation would be vacuous for it", dynamicSystem, len(legacy))
	}

	model := map[string][]string{}
	for _, p := range c.System.Policies {
		key, ok := corpusRowKeyOf(p.ID)
		if !ok {
			t.Fatalf("system-root policy %q does not carry a corpus identifier this guard can key back to a row", p.ID)
		}
		model[key] = append(model[key], p.ID)
	}
	notRepresented := map[string]bool{}
	for _, d := range c.Divergences {
		if d.Kind == DivergenceRowNotRepresented {
			notRepresented[d.Table+"/"+d.PolicyID] = true
		}
	}

	var inLegacyOnly, inModelOnly []string
	for key, from := range legacy {
		if len(model[key]) == 0 && !notRepresented[key] {
			inLegacyOnly = append(inLegacyOnly, fmt.Sprintf("%s (%s)", key, from))
		}
	}
	for key, ids := range model {
		if _, ok := legacy[key]; !ok {
			inModelOnly = append(inModelOnly, fmt.Sprintf("%s (policies %v)", key, ids))
		}
	}
	sort.Strings(inLegacyOnly)
	sort.Strings(inModelOnly)
	if len(inLegacyOnly) > 0 {
		t.Errorf("%d shipped control(s) are seeded as enabled system-tier rows and have no system-root policy and no declared "+
			"row_not_represented divergence - a control that exists in the legacy tables and not in the model:\n  %s",
			len(inLegacyOnly), strings.Join(inLegacyOnly, "\n  "))
	}
	if len(inModelOnly) > 0 {
		t.Errorf("%d system-root corpus polic(ies) come from no enabled system-tier row a migration seeds - a control that "+
			"exists in the model and not in the legacy tables:\n  %s", len(inModelOnly), strings.Join(inModelOnly, "\n  "))
	}
	declaredAbsent := 0
	for key := range legacy {
		if len(model[key]) == 0 && notRepresented[key] {
			declaredAbsent++
		}
	}
	t.Logf("legacy system tier: %d rows (%d static, %d dynamic); system document: %d policies from %d rows; declared not represented: %d",
		len(legacy), len(legacy)-dynamicSystem, dynamicSystem, len(c.System.Policies), len(model), declaredAbsent)
}

// TestEveryReproducedDefectImportsAsOne holds the corpus's reproduced-defect
// declarations to the census's disposition, in both directions and by reason.
//
// A row the census records as a preserved defect that the corpus does not
// declare as reproduced is a defect imported silently - which is a repair seen
// from the other side, and exactly what makes the shadow comparison disagree
// for a reason nobody can name. A declaration the census does not back is a
// defect invented. And a declaration naming different defect codes than the
// census is a report about a different migration.
func TestEveryReproducedDefectImportsAsOne(t *testing.T) {
	c := shippedCorpusFromDisk(t)
	census, err := registry.ShippedCensus()
	if err != nil {
		t.Fatalf("ShippedCensus: %v", err)
	}
	isDefect := map[string]bool{}
	for _, code := range DefectReasonCodes() {
		isDefect[string(code)] = true
	}

	want := map[string][]string{}
	for _, r := range census {
		if r.Disposition != string(StatusPreservedDefect) {
			continue
		}
		var codes []string
		for _, reason := range r.DispositionReasons {
			if isDefect[reason] {
				codes = append(codes, reason)
			}
		}
		want[r.PolicyID] = uniqueSorted(codes)
	}
	if len(want) == 0 {
		t.Fatal("the census records no preserved-defect row, so this comparison would be vacuous")
	}

	got := map[string][]string{}
	reproducedAnywhere := 0
	dynamicSeeds := forwardSeededDynamicRows(t)
	dynamicDeclared := map[string]bool{}
	for _, d := range c.Divergences {
		if d.Kind != DivergenceLegacyDefectReproduced {
			continue
		}
		reproducedAnywhere++
		var codes []string
		for _, line := range d.CompilerReasons {
			code, _, _ := strings.Cut(line, ":")
			if !isDefect[code] {
				t.Errorf("%s/%s declares a reproduced defect with reason %q, which is not a defect reason", d.Table, d.PolicyID, code)
			}
			codes = append(codes, code)
		}
		if len(codes) == 0 {
			t.Errorf("%s/%s declares a reproduced defect and names no defect reason", d.Table, d.PolicyID)
		}
		if !strings.Contains(d.Detail, "imports it as reproduced") {
			t.Errorf("%s/%s declares a reproduced defect whose detail does not say how it was imported: %q", d.Table, d.PolicyID, d.Detail)
		}
		if d.Table != "static_policies" {
			// NO CENSUS COVERS dynamic_policies, so without a database this test
			// holds a dynamic declaration to what the tree can answer: it names a
			// row a forward migration seeds, and only once. Whether that row
			// compiles as a preserved defect, and with which codes, is a fact about
			// the captured row's content. TestRegenerateTheShippedCorpusArtifact
			// holds it against a real capture in the Real-PG lane, which does not
			// run on the pull_request board.
			key := d.Table + "/" + d.PolicyID
			if dynamicDeclared[key] {
				t.Errorf("%s declares a reproduced defect twice", key)
			}
			dynamicDeclared[key] = true
			if _, seeded := dynamicSeeds[d.PolicyID]; d.Table != "dynamic_policies" || !seeded {
				t.Errorf("%s declares a reproduced defect for a row no forward migration seeds", key)
			}
			continue
		}
		if _, dup := got[d.PolicyID]; dup {
			t.Errorf("static_policies/%s declares a reproduced defect twice", d.PolicyID)
		}
		got[d.PolicyID] = uniqueSorted(codes)
	}

	var silent, invented, disagree []string
	for id, codes := range want {
		g, ok := got[id]
		switch {
		case !ok:
			silent = append(silent, id)
		case strings.Join(g, ",") != strings.Join(codes, ","):
			disagree = append(disagree, fmt.Sprintf("%s: census %v, corpus %v", id, codes, g))
		}
	}
	for id := range got {
		if _, ok := want[id]; !ok {
			invented = append(invented, id)
		}
	}
	sort.Strings(silent)
	sort.Strings(invented)
	sort.Strings(disagree)
	if len(silent) > 0 {
		t.Errorf("%d row(s) the census records as preserved_defect import with no legacy_defect_reproduced declaration - "+
			"a defect imported silently: %v", len(silent), silent)
	}
	if len(invented) > 0 {
		t.Errorf("%d row(s) declare a reproduced defect the census does not record: %v", len(invented), invented)
	}
	if len(disagree) > 0 {
		t.Errorf("%d reproduced-defect declaration(s) name different defect reasons than the census:\n  %s", len(disagree), strings.Join(disagree, "\n  "))
	}
	t.Logf("census preserved_defect rows: %d; static reproduced-defect declarations: %d; dynamic (held to seeded rows only): %d; across both tables: %d",
		len(want), len(got), len(dynamicDeclared), reproducedAnywhere)
}

// corpusRowKeyOf keys a corpus policy identifier back to its legacy row as
// "table/policy_id". A "#n" suffix names one of several policies from one row,
// and a per-scope variant's action one of a split row's policies (#4046); both
// key to the row through CorpusControlOf.
func corpusRowKeyOf(id string) (string, bool) {
	control, _, ok := CorpusControlOf(id)
	if !ok {
		return "", false
	}
	table, encoded, ok := strings.Cut(strings.TrimPrefix(control, "corpus:"), ":")
	if !ok {
		return "", false
	}
	policyID, ok := UnsanitizePolicyID(encoded)
	if !ok || table == "" {
		return "", false
	}
	return table + "/" + policyID, true
}

func uniqueSorted(in []string) []string {
	set := map[string]bool{}
	for _, s := range in {
		set[s] = true
	}
	return sortedSet(set)
}

// dynamicSeed is what the forward migrations leave a dynamic_policies row as.
type dynamicSeed struct {
	tier    string
	enabled bool
	file    string
}

var (
	dynamicInsertHeader = regexp.MustCompile(`(?is)insert\s+into\s+dynamic_policies\s*\(([^)]*)\)\s*values`)
	dynamicTierReset    = regexp.MustCompile(`(?is)^update\s+dynamic_policies\s+set\s+tier\s*=\s*'tenant'\s+where\s+tier\s*=\s*'system'\s+or\s+tier\s+is\s+null$`)
	dynamicDeleteByID   = regexp.MustCompile(`(?is)delete\s+from\s+dynamic_policies\s+where\s+policy_id\s*=\s*'([^']+)'$`)
	// dynamicGuardedDeleteByID is a DELETE that pins one policy_id and adds
	// conjuncts that keep an edited row, as core/179 does. The capture group is
	// the policy_id; an optional table alias qualifies the column.
	dynamicGuardedDeleteByID = regexp.MustCompile(`(?is)^delete\s+from\s+dynamic_policies(?:\s+[a-z_][a-z0-9_]*)?\s+where\s+(?:[a-z_][a-z0-9_]*\.)?policy_id\s*=\s*'([^']+)'\s+and\s+`)
	mentionsDynamic          = regexp.MustCompile(`(?is)(update|delete\s+from|insert\s+into)\s+dynamic_policies\b`)
)

// forwardSeededDynamicRows replays what the forward core migrations do to
// dynamic_policies, as far as tier, enabled and existence go.
//
// IT MODELS THREE STATEMENT SHAPES AND REFUSES EVERY OTHER ONE THAT COULD MOVE
// THE ANSWER. An INSERT (with its ON CONFLICT clause), the one tier reset core/031
// runs, and a DELETE by policy_id - unconditional, or guarded by conjuncts that
// keep an edited row (see freshChainProof and conjunctiveGuardedTail). Any other statement that inserts into,
// deletes from, or updates the tier of dynamic_policies fails the test naming
// the file: a parser that skipped a statement it did not understand would
// report the reconciliation clean against a legacy side that is not what a
// migrated database holds. UPDATEs that do not touch tier (action, condition and
// org-id rewrites) cannot change which rows are system-tier and are passed over.
//
// The capture the corpus is built from applies migrations/core only
// (scripts/legacy-policy-capture.sh), so that is the chain replayed here.
func forwardSeededDynamicRows(t *testing.T) map[string]dynamicSeed {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "..", "migrations", "core", "*.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 100 {
		t.Fatalf("found %d core migrations; the path is wrong or the tree is partial", len(files))
	}
	sort.Strings(files)
	rows := map[string]dynamicSeed{}
	for _, f := range files {
		if strings.HasSuffix(f, "_down.sql") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		base := filepath.Base(f)
		for _, stmt := range sqlStatements(string(raw)) {
			if !mentionsDynamic.MatchString(stmt) {
				continue
			}
			normalized := strings.Join(strings.Fields(stmt), " ")
			switch {
			case dynamicInsertHeader.MatchString(stmt):
				applyDynamicInsert(t, base, stmt, rows)
			case dynamicTierReset.MatchString(normalized):
				for id, r := range rows {
					if r.tier == "system" || r.tier == "" {
						r.tier = "tenant"
						rows[id] = r
					}
				}
			case regexp.MustCompile(`(?is)delete\s+from\s+dynamic_policies`).MatchString(stmt):
				tail := strings.TrimSpace(normalizeTail(stmt))
				if m := dynamicDeleteByID.FindStringSubmatch(tail); m != nil {
					delete(rows, m[1])
				} else if m := dynamicGuardedDeleteByID.FindStringSubmatch(tail); m != nil {
					if !conjunctiveGuardedTail(tail) {
						t.Fatalf("%s: a guarded DELETE FROM dynamic_policies whose WHERE is not one conjunction (a top-level OR, or RETURNING), so the replay cannot say which rows it removes: %q", base, normalized)
					}
					if err := freshChainProof(filepath.Join("..", "..", "agent"), base); err != nil {
						t.Fatal(err)
					}
					delete(rows, m[1])
				} else {
					t.Fatalf("%s: a DELETE FROM dynamic_policies this guard does not model: %q", base, normalized)
				}
			case regexp.MustCompile(`(?is)update\s+dynamic_policies\b.*\bset\b.*\btier\b`).MatchString(stmt):
				t.Fatalf("%s: an UPDATE of dynamic_policies.tier this guard does not model: %q", base, normalized)
			}
		}
	}
	return rows
}

// freshChainProof admits a DELETE guarded by conjuncts this replay does
// not evaluate. On the fresh chain replayed here the guarded row is the seed as
// seeded, which is the case such conjuncts are written to hold for - but whether
// they DO hold is a fact about the database, not the text. So the migration must
// carry its own real-Postgres test beside the agent's migration runner, which
// applies the chain and requires the delete to fire;
// TestEveryRealPostgresMigrationTestIsWiredIntoTheGate then requires that test to
// run. A guarded DELETE with no such test fails here, as an unmodelled one does.
//
// The proof must NAME the migration's file: a real-Postgres test that merely
// shares its number is not evidence about this statement.
func freshChainProof(agentDir, migration string) error {
	number, _, ok := strings.Cut(migration, "_")
	if !ok {
		return fmt.Errorf("%s: cannot read a migration number from the file name", migration)
	}
	proofs, err := filepath.Glob(filepath.Join(agentDir, "migration_"+number+"_*_realpg_test.go"))
	if err != nil {
		return err
	}
	for _, proof := range proofs {
		src, err := os.ReadFile(proof)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), migration) {
			return nil
		}
	}
	return fmt.Errorf("%s: a DELETE FROM dynamic_policies guarded by conjuncts this replay cannot evaluate, and no platform/agent/migration_%s_*_realpg_test.go that names %s proves it fires on a fresh chain", migration, number, migration)
}

// conjunctiveGuardedTail reports whether a guarded DELETE's WHERE is one
// conjunction: no OR and no RETURNING outside parentheses or a string literal.
// `policy_id = 'x' AND false OR true` deletes every row while pinning one, and
// the replay would record only the pinned id as removed.
func conjunctiveGuardedTail(stmt string) bool {
	s := strings.ToLower(stmt)
	ident := func(c byte) bool { return c == '_' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') }
	depth, quoted := 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quoted:
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
				} else {
					quoted = false
				}
			}
		case c == '\'':
			quoted = true
		case c == '(':
			depth++
		case c == ')':
			depth--
		case depth == 0 && (i == 0 || !ident(s[i-1])):
			for _, kw := range []string{"or", "returning"} {
				end := i + len(kw)
				if strings.HasPrefix(s[i:], kw) && (end == len(s) || !ident(s[end])) {
					return false
				}
			}
		}
	}
	return true
}

// normalizeTail keeps the part of a statement from its DELETE onwards, so a
// DELETE nested inside a DO block is matched on its own shape.
func normalizeTail(stmt string) string {
	i := strings.Index(strings.ToLower(stmt), "delete")
	return strings.Join(strings.Fields(stmt[i:]), " ")
}

// applyDynamicInsert applies one INSERT INTO dynamic_policies.
func applyDynamicInsert(t *testing.T, file, stmt string, rows map[string]dynamicSeed) {
	t.Helper()
	loc := dynamicInsertHeader.FindStringSubmatchIndex(stmt)
	var cols []string
	for _, c := range strings.Split(stmt[loc[2]:loc[3]], ",") {
		cols = append(cols, strings.ToLower(strings.TrimSpace(c)))
	}
	idx := func(name string) int {
		for i, c := range cols {
			if c == name {
				return i
			}
		}
		return -1
	}
	idCol, tierCol, enabledCol := idx("policy_id"), idx("tier"), idx("enabled")
	if idCol < 0 {
		t.Fatalf("%s: an INSERT INTO dynamic_policies names no policy_id column", file)
	}
	tuples, tail := sqlTuples(stmt[loc[1]:])
	if len(tuples) == 0 {
		t.Fatalf("%s: an INSERT INTO dynamic_policies with no VALUES tuple this guard can read", file)
	}
	conflict := strings.ToLower(strings.Join(strings.Fields(tail), " "))
	updatesTier := strings.Contains(conflict, "do update set") && strings.Contains(conflict, "tier = excluded.tier")
	updatesEnabled := strings.Contains(conflict, "do update set") && strings.Contains(conflict, "enabled = excluded.enabled")
	keepsExisting := strings.Contains(conflict, "do nothing")
	if conflict != "" && !keepsExisting && !strings.Contains(conflict, "do update set") {
		t.Fatalf("%s: an INSERT INTO dynamic_policies with an ON CONFLICT clause this guard does not model: %q", file, conflict)
	}
	for _, tuple := range tuples {
		if len(tuple) != len(cols) {
			t.Fatalf("%s: a dynamic_policies tuple has %d values for %d columns: %v", file, len(tuple), len(cols), tuple)
		}
		id := sqlLiteral(tuple[idCol])
		seed := dynamicSeed{tier: "tenant", enabled: true, file: file}
		if tierCol >= 0 {
			seed.tier = sqlLiteral(tuple[tierCol])
		}
		if enabledCol >= 0 {
			seed.enabled = strings.EqualFold(strings.TrimSpace(tuple[enabledCol]), "true")
		}
		prev, exists := rows[id]
		switch {
		case !exists:
			rows[id] = seed
		case keepsExisting:
		default:
			next := prev
			if updatesTier {
				next.tier = seed.tier
			}
			if updatesEnabled {
				next.enabled = seed.enabled
			}
			next.file = file
			rows[id] = next
		}
	}
}

// sqlStatements splits SQL on semicolons that are outside single-quoted
// literals, with line comments removed first. Dollar-quoted bodies are not
// treated as literals: a DO block splits into fragments, which is enough for
// the statement shapes matched above.
func sqlStatements(src string) []string {
	var out []string
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if !inQuote && c == '-' && i+1 < len(src) && src[i+1] == '-' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
			continue
		}
		if c == '\'' {
			if inQuote && i+1 < len(src) && src[i+1] == '\'' {
				b.WriteString("''")
				i++
				continue
			}
			inQuote = !inQuote
		}
		if c == ';' && !inQuote {
			out = append(out, b.String())
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	if strings.TrimSpace(b.String()) != "" {
		out = append(out, b.String())
	}
	return out
}

// sqlTuples reads the top-level VALUES tuples at the start of s and returns each
// tuple's top-level values as raw text, plus whatever follows the last tuple.
func sqlTuples(s string) ([][]string, string) {
	var tuples [][]string
	var cur []string
	var val strings.Builder
	depth := 0
	inQuote := false
	last := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			val.WriteByte(c)
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					val.WriteByte('\'')
					i++
					continue
				}
				inQuote = false
			}
			continue
		}
		switch {
		case c == '\'':
			inQuote = true
			val.WriteByte(c)
		case c == '(':
			depth++
			if depth == 1 {
				cur, val = nil, strings.Builder{}
				continue
			}
			val.WriteByte(c)
		case c == ')':
			depth--
			if depth == 0 {
				cur = append(cur, strings.TrimSpace(val.String()))
				tuples = append(tuples, cur)
				last = i + 1
				continue
			}
			val.WriteByte(c)
		case c == ',' && depth == 1:
			cur = append(cur, strings.TrimSpace(val.String()))
			val.Reset()
		case depth == 0 && c != ',' && c != ' ' && c != '\n' && c != '\t' && c != '\r':
			return tuples, s[i:]
		default:
			if depth >= 1 {
				val.WriteByte(c)
			}
		}
	}
	return tuples, s[last:]
}

// sqlLiteral returns a single-quoted SQL literal's value, with any cast removed.
func sqlLiteral(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.Index(v, "::"); i > 0 && strings.HasSuffix(strings.TrimSpace(v[:i]), "'") {
		v = strings.TrimSpace(v[:i])
	}
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return strings.ReplaceAll(v[1:len(v)-1], "''", "'")
	}
	return v
}

// TestAGuardedDeleteIsAdmittedOnlyWhenItsWhereIsOneConjunction plants the
// shapes that pin one policy_id and still delete others, beside the real
// core/179 statement and conjunctions whose OR sits where it cannot widen the
// delete.
func TestAGuardedDeleteIsAdmittedOnlyWhenItsWhereIsOneConjunction(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "migrations", "core", "179_delete_inert_sensitive_data_control.sql"))
	if err != nil {
		t.Fatal(err)
	}
	real179 := ""
	for _, stmt := range sqlStatements(string(raw)) {
		if regexp.MustCompile(`(?is)delete\s+from\s+dynamic_policies`).MatchString(stmt) {
			real179 = strings.TrimSpace(normalizeTail(stmt))
		}
	}
	cases := map[string]bool{
		real179: true,
		`DELETE FROM dynamic_policies WHERE policy_id = 'x' AND name = 'a or b'`:                             true,
		`DELETE FROM dynamic_policies dp WHERE dp.policy_id = 'x' AND EXISTS (SELECT 1 FROM t WHERE a OR b)`: true,
		`DELETE FROM dynamic_policies WHERE policy_id = 'x' AND ordering = 1`:                                true,
		`DELETE FROM dynamic_policies WHERE policy_id = 'x' AND false OR true`:                               false,
		`DELETE FROM dynamic_policies WHERE policy_id = 'x' AND enabled OR tier = 'tenant'`:                  false,
		`DELETE FROM dynamic_policies WHERE policy_id = 'x' AND (1=1) OR policy_id LIKE 'sys_%'`:             false,
		`DELETE FROM dynamic_policies WHERE policy_id = 'x' AND 1=1 RETURNING *`:                             false,
	}
	for stmt, want := range cases {
		if dynamicGuardedDeleteByID.FindStringSubmatch(stmt) == nil {
			t.Fatalf("planted statement is not the guarded shape at all, so it tests nothing: %q", stmt)
		}
		if got := conjunctiveGuardedTail(stmt); got != want {
			t.Errorf("conjunctiveGuardedTail(%q) = %v, want %v", stmt, got, want)
		}
	}
}

// TestAFreshChainProofMustNameItsMigration: a real-Postgres test that shares a
// migration's number but not its file is not a proof about that migration.
func TestAFreshChainProofMustNameItsMigration(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("migration_900_other_realpg_test.go", `package agent // reads 900_something_else.sql`)
	if err := freshChainProof(dir, "900_delete_a_row.sql"); err == nil {
		t.Error("a proof sharing only the number was accepted")
	}
	write("migration_900_delete_a_row_realpg_test.go", `package agent // reads 900_delete_a_row.sql`)
	if err := freshChainProof(dir, "900_delete_a_row.sql"); err != nil {
		t.Errorf("a proof naming the migration was refused: %v", err)
	}
	if err := freshChainProof(dir, "901_delete_a_row.sql"); err == nil {
		t.Error("a migration with no proof at all was accepted")
	}
	if err := freshChainProof(filepath.Join("..", "..", "agent"), "179_delete_inert_sensitive_data_control.sql"); err != nil {
		t.Errorf("core/179's own proof was refused: %v", err)
	}
}
