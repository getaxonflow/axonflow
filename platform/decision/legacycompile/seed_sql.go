// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// THE SEED MIGRATIONS, READ AS DATA (#4254).
//
// Two tests read what migrations/core seeds: the canary corpus's check that
// every payload fires the row it names, and the orchestrator's check that the
// dynamic condition matcher produces every fact the shipped dynamic controls
// read. Both read the SQL itself rather than a copy of its rows, because a copy
// is a second statement of the seed and the one that drifts is the one nobody
// runs against a real row. This reader is the one extraction both use; it moved
// here, unchanged, from canary_payload_rows_test.go.

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

// readSeedInserts parses every INSERT statement of the migrations at paths.
func readSeedInserts(paths []string) ([]insertStmt, error) {
	var out []insertStmt
	for _, path := range paths {
		src, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
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
		return nil, fmt.Errorf("parsed zero INSERT statements from %v; the extraction is broken", paths)
	}
	return out, nil
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

// withoutCast strips a trailing Postgres cast from a value, so a literal written
// with its type (`'[...]'::jsonb`, as core/173 writes its conditions) reads as
// the literal. A value whose last quote is not followed by `::name` is returned
// unchanged, and unquote then judges it as before.
func withoutCast(v string) string {
	v = strings.TrimSpace(v)
	i := strings.LastIndex(v, "'")
	if i < 0 || i == len(v)-1 {
		return v
	}
	rest := strings.TrimSpace(v[i+1:])
	name, isCast := strings.CutPrefix(rest, "::")
	if !isCast || name == "" || strings.ContainsAny(name, " '(),") {
		return v
	}
	return v[:i+1]
}

// SeedDynamicConditions returns, for every dynamic_policies row the migrations
// at paths insert, its policy_id and its conditions document as stored.
//
// A dynamic_policies INSERT that names no policy_id or conditions column, or a
// row that does not quote both, is refused rather than skipped: a reader that
// quietly dropped a row would report that row's facts as never needed.
func SeedDynamicConditions(paths ...string) (map[string]string, error) {
	stmts, err := readSeedInserts(paths)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, st := range stmts {
		if st.table != "dynamic_policies" {
			continue
		}
		idAt, condAt := colIndex(st.cols, "policy_id"), colIndex(st.cols, "conditions")
		if condAt < 0 {
			condAt = colIndex(st.cols, "condition")
		}
		if idAt < 0 || condAt < 0 {
			return nil, fmt.Errorf("a dynamic_policies INSERT in %v names no policy_id or conditions column: %v", paths, st.cols)
		}
		for _, tup := range splitTuples(st.body) {
			// A row has exactly one value per column. The statement body runs to
			// its terminating semicolon, so it also carries every parenthesised
			// group after the last row - an ON CONFLICT column list, for one -
			// and such a group is not a row of this INSERT.
			if len(tup) != len(st.cols) {
				continue
			}
			id, idOK := unquote(withoutCast(tup[idAt]))
			cond, condOK := unquote(withoutCast(tup[condAt]))
			if !idOK || !condOK {
				return nil, fmt.Errorf("a dynamic_policies row in %v does not quote its policy_id or conditions: %q, %q", paths, tup[idAt], tup[condAt])
			}
			out[id] = cond
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the migrations at %v insert no dynamic_policies row", paths)
	}
	return out, nil
}
