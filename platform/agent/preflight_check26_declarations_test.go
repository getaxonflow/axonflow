// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// preflightQueryDecl is how the upgrade preflight declares check 26's queries:
// one line holding one double-quoted string each, so the bytes a preflight
// run sends are the bytes this test runs.
var preflightQueryDecl = regexp.MustCompile(`(?m)^(C26_[A-Z_]+)="([^"]+)"$`)

// preflightCheck26QueryNames are the queries check 26 declares, in declaration
// order: the columns and the shared body of its two lists, the two lists, and
// the count and listing wrapped around each.
var preflightCheck26QueryNames = []string{
	"C26_SELECT", "C26_ELIGIBLE", "C26_CANDIDATES", "C26_TENANT_ROWS",
	"C26_COUNT_SQL", "C26_TENANT_COUNT_SQL", "C26_LIST_SQL", "C26_TENANT_LIST_SQL",
}

// preflightCheck26Lists is how the two lists must be declared: one body, with
// the tenant term and with it reversed, so no edit reaches one and misses the
// other.
var preflightCheck26Lists = map[string]string{
	"C26_CANDIDATES":  "$C26_SELECT $C26_ELIGIBLE AND po.tenant_id IS NULL",
	"C26_TENANT_ROWS": "$C26_SELECT $C26_ELIGIBLE AND po.tenant_id IS NOT NULL",
}

// preflightShellCode is the preflight with its full-line comments blanked, so
// a name a comment mentions is not read as a use of it.
func preflightShellCode(b []byte) string {
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimLeft(l, " \t"), "#") {
			lines[i] = ""
		}
	}
	return strings.Join(lines, "\n")
}

// preflightCheck26Queries reads check 26's queries out of the shipped preflight,
// with each $C26_ reference expanded as bash expands it inside the double
// quotes. It fails unless each query's declaration is its only writer.
func preflightCheck26Queries(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "scripts", "deployment", "v9_self_hosted_preflight.sh"))
	if err != nil {
		t.Fatalf("reading the upgrade preflight: %v", err)
	}
	declared := map[string][]string{}
	for _, m := range preflightQueryDecl.FindAllSubmatch(b, -1) {
		declared[string(m[1])] = append(declared[string(m[1])], string(m[2]))
	}
	out := map[string]string{}
	for _, name := range preflightCheck26QueryNames {
		if len(declared[name]) != 1 {
			t.Fatalf("the preflight declares %s %d time(s); want exactly one single-line declaration", name, len(declared[name]))
		}
		out[name] = declared[name][0]
	}
	// Bash sends the value a name holds when the wrapper around it expands, so
	// a second writer could send SQL this test never runs. Every writer that
	// spells the name (an assignment anywhere on a line, +=, export, declare,
	// local or readonly with any flags, printf -v, read, eval, an array
	// element) names it without a leading $, and a read names it after $ or ${.
	// So outside comments each name may appear bare exactly once, at its
	// declaration; a ${NAME:=...} or ${NAME=...} default, which writes it, is
	// refused outright. A name built at run time (printf -v "C26_$k") is
	// outside what this can see, and the script has none.
	code := preflightShellCode(b)
	for _, name := range preflightCheck26QueryNames {
		bare := 0
		for _, m := range regexp.MustCompile(`(\$\{?)?\b`+name+`\b`).FindAllStringSubmatch(code, -1) {
			if m[1] == "" {
				bare++
			}
		}
		if bare != 1 {
			t.Fatalf("outside comments the preflight names %s without a leading $ %d time(s); want once, its declaration, since any other is a write of it", name, bare)
		}
		if regexp.MustCompile(`\$\{` + name + `:?=`).MatchString(code) {
			t.Fatalf("the preflight writes %s through a ${%s:=...} default; its declaration must be its only writer", name, name)
		}
	}
	for name, want := range preflightCheck26Lists {
		if out[name] != want {
			t.Fatalf("the preflight declares %s as %q; want %q", name, out[name], want)
		}
	}
	// A reference is always to a name declared above it, so expanding in
	// declaration order resolves every one.
	for _, name := range preflightCheck26QueryNames {
		q := out[name]
		for _, ref := range preflightCheck26QueryNames {
			q = strings.ReplaceAll(q, "$"+ref, out[ref])
		}
		if strings.Contains(q, "$") {
			t.Fatalf("%s still holds a shell expansion this test cannot reproduce: %s", name, q)
		}
		out[name] = q
	}
	return out
}

// TestThePreflightDeclaresEachCheck26QueryOnce holds check 26's declarations
// without a database, so the agent's unit tests run it, and a change to the
// preflight runs them (test.yml's go-code filter, and test-community.yml's,
// list the script): each query has one writer, the two lists are one body with the
// tenant term and with it reversed, and every reference expands. The
// real-Postgres test then runs the same queries against the import they
// preview.
func TestThePreflightDeclaresEachCheck26QueryOnce(t *testing.T) {
	q := preflightCheck26Queries(t)
	for _, name := range preflightCheck26QueryNames {
		if strings.TrimSpace(q[name]) == "" {
			t.Errorf("%s expands to nothing", name)
		}
	}
}
