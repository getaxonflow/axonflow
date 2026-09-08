// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The seed migrations the canary's corpus claims to fire rows from.
var canarySeedMigrations = []string{
	"../../../migrations/core/031_seed_system_policies.sql",
	"../../../migrations/core/059_dangerous_command_policies.sql",
}

// TestEveryCanaryPayloadFiresTheRowItNames is #3602's central claim, checked
// instead of declared (R3 round 1, finding F17).
//
// # THE CLAIM, AND WHY NOTHING WAS CHECKING IT
//
// Each payload in the canary's corpus carries a `row` field naming the seeded
// policy it is built to trip - `sys_pii_ssn`, `sys_sqli_union_select`,
// `sys_dangerous_credential_access`. That claim is the whole argument that the
// corpus is ADVERSARIAL rather than benign: a payload that fires nothing
// produces a comparison in which both engines had no policy to disagree about,
// which classifies `match` for free and gives the plane a denominator made of
// questions that could not have had two answers.
//
// TestTheCanaryPayloadCorpusIsAdversarial checks the SHAPE of that claim - six
// distinct rows, three categories, both directions - and cannot check its
// TRUTH. A payload could name `sys_pii_ssn` and contain "hello", and every guard
// in this package would stay green while the window filled with nothing.
//
// # IT IS DERIVED FROM THE MIGRATIONS, NOT FROM A COPY OF THE REGEXES
//
// The patterns are read out of the seed SQL and applied to the payload text. A
// table of expected patterns beside the corpus would be a third statement of
// them - after the migration and the database - and the one that drifted would
// be the one nobody runs against a real row.
//
// Go's RE2 does not implement `(?i)` inline flags the same way everywhere and
// does not implement backreferences at all, and the seeded patterns are written
// for Postgres. Where a pattern will not compile in RE2 the test says so and
// skips THAT PATTERN, counting it - and fails if too many are skipped, because a
// test that quietly could not read most of the corpus is a test that checks
// nothing.
func TestEveryCanaryPayloadFiresTheRowItNames(t *testing.T) {
	patterns, uncompilable := seededPatterns(t)
	dynamic := dynamicContains(t)
	if len(dynamic) == 0 {
		t.Fatal("read zero dynamic rows with a contains_any condition; the corpus names two " +
			"(sys_dyn_hipaa, sys_dyn_financial) and their claims would go unchecked")
	}
	if len(patterns) == 0 {
		t.Fatal("read zero seeded policy patterns; the extraction is broken and every claim " +
			"below would pass over nothing")
	}
	// The seed files carry ~60 rows between them. A run that could compile only
	// a handful is a run whose verdict is about RE2, not about the corpus.
	if uncompilable*2 > len(patterns) {
		t.Fatalf("more than half the seeded patterns (%d of %d) would not compile in RE2; this "+
			"test cannot honestly report on the corpus", uncompilable, len(patterns)+uncompilable)
	}
	t.Logf("read %d seeded patterns (%d skipped as RE2-uncompilable)", len(patterns), uncompilable)

	for _, p := range canaryPayloads(t) {
		if p.Row == "" {
			// A benign entry names no row, and must fire NOTHING that blocks -
			// see the second half of this test.
			continue
		}
		if vals, isDynamic := dynamic[p.Row]; isDynamic {
			// A DYNAMIC row has no pattern: it fires on a contains_any
			// condition, so the claim is that the payload carries one of the
			// row's own declared trigger words.
			hit := false
			for _, v := range vals {
				if strings.Contains(strings.ToLower(p.Text), strings.ToLower(v)) {
					hit = true
					break
				}
			}
			if !hit {
				t.Errorf("payload %q names DYNAMIC row %q and carries none of its contains_any "+
					"values %v.\n  text: %s\n\nThe row does not fire, so the comparison is one "+
					"neither engine could disagree about.", p.ID, p.Row, vals, p.Text)
			}
			continue
		}
		re, ok := patterns[p.Row]
		if !ok {
			t.Errorf("payload %q claims to fire row %q, which no seed migration declares.\n\n"+
				"Either the row was renamed - in which case this payload now fires nothing and "+
				"contributes a comparison neither engine could disagree about - or the name is a "+
				"typo nobody would ever see, because a payload that matches no row still returns "+
				"200 and still counts as an evaluated probe.", p.ID, p.Row)
			continue
		}
		if !re.MatchString(p.Text) {
			t.Errorf("payload %q does NOT match the pattern of the row it names (%s).\n\n"+
				"  pattern: %s\n  text:    %s\n\n"+
				"The payload fires nothing, so both engines produce an empty verdict, the pair "+
				"classifies `match` for free, and the plane's denominator grows by a comparison "+
				"that could not have had two answers. That is a window that is non-vacuous and "+
				"worthless at the same time - the most expensive outcome, because it SATISFIES "+
				"the gate.", p.ID, p.Row, re.String(), p.Text)
		}
	}
}

// TestNoAllowPayloadTripsABlockingRow keeps the corpus's OTHER half honest.
//
// Two payloads carry `expect: "allow"` with no row, and the canary's evidence
// predicate reads that field. If one of them happens to match a `block` row -
// an SSN-shaped number in a "benign" sentence, a stray `OR 1=1` - the probe is
// denied, the run reports it as an unexpected outcome, and the allow path this
// corpus is supposed to measure is not measured at all. That is the one half
// where all six UNEXPLAINED comparisons on the v10.4.0 gate (b) run turned out
// to live.
func TestNoAllowPayloadTripsABlockingRow(t *testing.T) {
	patterns, _ := seededPatterns(t)
	blocking := blockingRows(t)
	if len(blocking) == 0 {
		t.Fatal("read zero rows with action 'block'; the extraction is broken and this test " +
			"would pass over nothing")
	}

	checked := 0
	for _, p := range canaryPayloads(t) {
		if p.Expect != "allow" || p.Row != "" {
			continue
		}
		checked++
		for row := range blocking {
			re, ok := patterns[row]
			if !ok {
				continue
			}
			if re.MatchString(p.Text) {
				t.Errorf("payload %q is declared expect=\"allow\" but matches BLOCKING row %q.\n\n"+
					"  pattern: %s\n  text:    %s\n\n"+
					"It will be denied, the probe's expectation is wrong, and the clean path this "+
					"corpus exists to also measure is not measured.", p.ID, row, re.String(), p.Text)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no rowless expect=\"allow\" payload was checked. Either the corpus lost its " +
			"benign entries - in which case every observation on every plane is a block, and the " +
			"allow path is unmeasured - or this test's selector is wrong.")
	}
}

// --- extraction ---
//
// THE COLUMN POSITIONS ARE DERIVED FROM EACH INSERT'S OWN COLUMN LIST, not
// assumed. The two seed migrations declare DIFFERENT orders - 031 has
// `policy_id, name, category, tier, pattern, …` and 059 has
// `policy_id, name, category, pattern, …` - so a positional regex tuned to one
// reads the SEVERITY of the other as its pattern. The first version of this file
// did exactly that and reported four payloads as matching `(?i)high` and
// `(?i)critical`. A test whose extraction is wrong reports on the extraction.

// insertStmt is one INSERT ... (cols) VALUES (…),(…); statement.
type insertStmt struct {
	table string
	cols  []string
	body  string
}

// insertHeadRe matches the statement HEAD only. The body is scanned rather than
// matched, because a `(.*?);` body terminates at the first semicolon - and a
// seeded SQL-injection pattern contains one: `'(?i);\s*DROP\s+(TABLE|DATABASE)\b'`.
// That truncated the 031 statement mid-way and silently dropped 35 of 73 rows,
// so `sys_sqli_stacked_drop` read as "no seed migration declares it" when line
// 71 declares it. A test whose extraction is wrong reports on the extraction.
var insertHeadRe = regexp.MustCompile(`(?is)INSERT\s+INTO\s+(\w+)\s*\(([^)]*)\)\s*VALUES`)

// statementBody returns everything from `from` to the first semicolon that is
// NOT inside a single-quoted string.
func statementBody(src string, from int) string {
	inStr := false
	for i := from; i < len(src); i++ {
		switch src[i] {
		case '\'':
			if inStr && i+1 < len(src) && src[i+1] == '\'' {
				i++
				continue
			}
			inStr = !inStr
		case ';':
			if !inStr {
				return src[from:i]
			}
		}
	}
	return src[from:]
}

func seedInserts(t *testing.T) []insertStmt {
	t.Helper()
	var out []insertStmt
	for _, path := range canarySeedMigrations {
		src, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("reading %s: %v.\n\nThe seed migrations moved; this test addresses them by "+
				"path and would otherwise silently check nothing.", path, err)
		}
		body := string(src)
		for _, loc := range insertHeadRe.FindAllStringSubmatchIndex(body, -1) {
			m := []string{
				body[loc[0]:loc[1]],
				body[loc[2]:loc[3]],
				body[loc[4]:loc[5]],
				statementBody(body, loc[1]),
			}
			var cols []string
			for _, c := range strings.Split(m[2], ",") {
				c = strings.TrimSpace(c)
				// A `--` comment can sit inside the column list.
				if i := strings.Index(c, "--"); i >= 0 {
					c = strings.TrimSpace(c[:i])
				}
				if c != "" {
					cols = append(cols, c)
				}
			}
			out = append(out, insertStmt{table: m[1], cols: cols, body: m[3]})
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed zero INSERT statements from the seed migrations; the extraction is broken")
	}
	return out
}

// splitTuples returns each `( … )` tuple's fields, respecting single-quoted
// strings (which contain commas, parentheses and doubled quotes).
func splitTuples(body string) [][]string {
	var tuples [][]string
	var cur []string
	var field strings.Builder
	depth, inStr := 0, false
	for i := 0; i < len(body); i++ {
		c := body[i]
		if inStr {
			if c == '\'' {
				if i+1 < len(body) && body[i+1] == '\'' {
					field.WriteByte(c)
					field.WriteByte(body[i+1])
					i++
					continue
				}
				inStr = false
			}
			field.WriteByte(c)
			continue
		}
		switch c {
		case '\'':
			inStr = true
			field.WriteByte(c)
		case '(':
			depth++
			if depth > 1 {
				field.WriteByte(c)
			}
		case ')':
			depth--
			if depth == 0 {
				cur = append(cur, strings.TrimSpace(field.String()))
				field.Reset()
				tuples = append(tuples, cur)
				cur = nil
			} else {
				field.WriteByte(c)
			}
		case ',':
			if depth == 1 {
				cur = append(cur, strings.TrimSpace(field.String()))
				field.Reset()
			} else if depth > 1 {
				field.WriteByte(c)
			}
		default:
			if depth >= 1 {
				field.WriteByte(c)
			}
		}
	}
	return tuples
}

func colIndex(cols []string, name string) int {
	for i, c := range cols {
		if c == name {
			return i
		}
	}
	return -1
}

// unquote strips the SQL single quotes and un-doubles the escapes.
func unquote(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) < 2 || v[0] != '\'' || v[len(v)-1] != '\'' {
		return "", false
	}
	return strings.ReplaceAll(v[1:len(v)-1], "''", "'"), true
}

// seededPatterns returns row id -> compiled pattern for every STATIC row, and
// how many patterns RE2 could not compile.
func seededPatterns(t *testing.T) (map[string]*regexp.Regexp, int) {
	t.Helper()
	out := map[string]*regexp.Regexp{}
	skipped := 0
	for _, st := range seedInserts(t) {
		if st.table != "static_policies" {
			continue
		}
		idAt, patAt := colIndex(st.cols, "policy_id"), colIndex(st.cols, "pattern")
		if idAt < 0 || patAt < 0 {
			continue
		}
		for _, tup := range splitTuples(st.body) {
			if idAt >= len(tup) || patAt >= len(tup) {
				continue
			}
			id, ok := unquote(tup[idAt])
			if !ok {
				continue
			}
			pattern, ok := unquote(tup[patAt])
			if !ok || strings.TrimSpace(pattern) == "" {
				continue
			}
			// Case-insensitively is the CONSERVATIVE direction: it can only make
			// a payload match, and a payload that matches only case-insensitively
			// still fires the row in production, where several of these patterns
			// carry their own (?i).
			re, err := regexp.Compile(`(?i)` + pattern)
			if err != nil {
				skipped++
				continue
			}
			out[id] = re
		}
	}
	return out, skipped
}

// dynamicContains returns row id -> the `contains_any` values of its condition,
// for the DYNAMIC rows.
//
// They have no `pattern` column at all: a dynamic row fires on a JSON condition,
// and the two the corpus names (`sys_dyn_hipaa`, `sys_dyn_financial`) both use
// `{"field":"query","operator":"contains_any","value":[…]}`. Checking that a
// payload contains one of those values is the same claim as a regex match, made
// against the row's own declared trigger rather than against a copy of it.
func dynamicContains(t *testing.T) map[string][]string {
	t.Helper()
	valuesRe := regexp.MustCompile(`"operator"\s*:\s*"contains_any"\s*,\s*"value"\s*:\s*\[([^\]]*)\]`)
	out := map[string][]string{}
	for _, st := range seedInserts(t) {
		if st.table != "dynamic_policies" {
			continue
		}
		idAt, condAt := colIndex(st.cols, "policy_id"), colIndex(st.cols, "conditions")
		if condAt < 0 {
			condAt = colIndex(st.cols, "condition")
		}
		if idAt < 0 || condAt < 0 {
			continue
		}
		for _, tup := range splitTuples(st.body) {
			if idAt >= len(tup) || condAt >= len(tup) {
				continue
			}
			id, ok := unquote(tup[idAt])
			if !ok {
				continue
			}
			cond, ok := unquote(tup[condAt])
			if !ok {
				continue
			}
			m := valuesRe.FindStringSubmatch(cond)
			if m == nil {
				continue
			}
			var vals []string
			for _, v := range strings.Split(m[1], ",") {
				if s, ok := unquoteJSON(v); ok {
					vals = append(vals, s)
				}
			}
			if len(vals) > 0 {
				out[id] = vals
			}
		}
	}
	return out
}

func unquoteJSON(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", false
	}
	return v[1 : len(v)-1], true
}

// blockingRows returns the ids of every seeded static row whose action is
// `block`, with the action column found by NAME.
func blockingRows(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, st := range seedInserts(t) {
		if st.table != "static_policies" {
			continue
		}
		idAt, actAt := colIndex(st.cols, "policy_id"), colIndex(st.cols, "action")
		if idAt < 0 || actAt < 0 {
			continue
		}
		for _, tup := range splitTuples(st.body) {
			if idAt >= len(tup) || actAt >= len(tup) {
				continue
			}
			id, ok := unquote(tup[idAt])
			if !ok {
				continue
			}
			if act, ok := unquote(tup[actAt]); ok && act == "block" {
				out[id] = true
			}
		}
	}
	return out
}
