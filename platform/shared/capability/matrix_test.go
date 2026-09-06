// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// matrixPath is the living feature matrix this census reconciles against.
const matrixPath = "technical-docs/COMMUNITY_ENTERPRISE_FEATURE_MATRIX.md"

// tierLimitsPath is the COMMUNITY half of the ADR-029 build-tag pair that
// carries the tier limit tables.
//
// The community half is used on purpose: it is the one that survives on the
// mirror, so this reconciliation runs in both trees. The enterprise half
// (tier_support.go) carries the same three tables, and keeping the two in
// lockstep is that package's own problem, pinned by its tier boundary tests.
const tierLimitsPath = "platform/agent/license/tier.go"

// readMatrix returns the matrix source, or skips when this is the mirror.
//
// The skip fires ONLY when technical-docs/ is absent as a whole, which is the
// community sync's own exclusion and nothing else. A tree that has the
// directory and not the file FAILS: that is a deleted matrix, not a stripped
// one, and the difference is the whole reason this is not a bare os.Stat on the
// file.
func readMatrix(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "technical-docs")); err != nil {
		t.Skip("community mirror: technical-docs/ is excluded from the sync")
	}
	b, err := os.ReadFile(filepath.Join(root, matrixPath))
	if err != nil {
		t.Fatalf("this tree has technical-docs/ but not the living feature matrix: %v", err)
	}
	if len(b) < 1000 {
		t.Fatalf("%s is %d bytes; a truncated matrix would make every reconciliation "+
			"below agree with it vacuously", matrixPath, len(b))
	}
	return string(b)
}

// matrixHeadings returns the `###` section headings of the matrix.
func matrixHeadings(src string) []string {
	var out []string
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(line, "### ") {
			out = append(out, strings.TrimSpace(strings.TrimPrefix(line, "### ")))
		}
		if strings.HasPrefix(line, "## ") && !strings.HasPrefix(line, "### ") {
			out = append(out, strings.TrimSpace(strings.TrimPrefix(line, "## ")))
		}
	}
	return out
}

// TestEveryMatrixSectionIsEitherClaimedOrExcluded is the two-sided
// reconciliation. Either direction alone accepts a registry that has quietly
// stopped covering half the document it claims to reconcile against.
func TestEveryMatrixSectionIsEitherClaimedOrExcluded(t *testing.T) {
	src := readMatrix(t)
	headings := matrixHeadings(src)
	if len(headings) < 10 {
		t.Fatalf("found %d headings in the matrix; the parser has stopped working and "+
			"every check below is about an empty set", len(headings))
	}
	inMatrix := map[string]bool{}
	for _, h := range headings {
		inMatrix[h] = true
	}

	claimed := map[string][]string{}
	for _, e := range Load().Entries {
		for _, h := range e.Matrix {
			claimed[h] = append(claimed[h], e.ID)
		}
	}
	excluded := map[string]string{}
	for _, s := range Load().MatrixSectionsOutOfScope {
		excluded[s.Heading] = s.Reason
	}

	// Direction 1: everything a capability claims must exist in the matrix.
	for heading, ids := range claimed {
		if !inMatrix[heading] {
			t.Errorf("capabilities %v name matrix section %q, which the matrix does not "+
				"have. Either the section was renamed or the claim was invented",
				ids, heading)
		}
		if _, alsoExcluded := excluded[heading]; alsoExcluded {
			t.Errorf("matrix section %q is both claimed by %v and declared out of scope",
				heading, ids)
		}
	}
	// Direction 2: everything in the matrix must be claimed or excluded.
	var unaccounted []string
	for _, h := range headings {
		if len(claimed[h]) > 0 {
			continue
		}
		if _, ok := excluded[h]; ok {
			continue
		}
		unaccounted = append(unaccounted, h)
	}
	sort.Strings(unaccounted)
	if len(unaccounted) > 0 {
		t.Errorf("%d matrix section(s) are neither claimed by a capability nor declared "+
			"out of scope:\n  %s\n\nAdd the section to a capability's `matrix` field, or "+
			"to matrix_sections_out_of_scope with a reason.",
			len(unaccounted), strings.Join(unaccounted, "\n  "))
	}
	// Direction 3: an exclusion whose section has gone is stale.
	for heading := range excluded {
		if !inMatrix[heading] {
			t.Errorf("matrix section %q is declared out of scope but no longer exists in "+
				"the matrix; the exclusion is stale", heading)
		}
	}
}

// --- the limits reconciliation ----------------------------------------------

// tierLimits parses the three TierLimits composite literals out of the licence
// package with go/ast and returns field -> value per tier.
//
// It PARSES rather than greps for the same reason the route derivation does: a
// grep for `TenantPolicies:\s*(\d+)` finds three matches with no way to say
// which tier each belongs to, and would answer confidently after a refactor
// moved one of them.
func tierLimits(t *testing.T) map[string]map[string]int {
	t.Helper()
	full := filepath.Join(repoRoot(t), tierLimitsPath)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, full, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", tierLimitsPath, err)
	}
	out := map[string]map[string]int{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.CompositeLit)
				if !ok {
					continue
				}
				if ident, ok := lit.Type.(*ast.Ident); !ok || ident.Name != "TierLimits" {
					continue
				}
				fields := map[string]int{}
				for _, el := range lit.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok {
						continue
					}
					if v, ok := intValue(kv.Value); ok {
						fields[key.Name] = v
					}
				}
				out[name.Name] = fields
			}
		}
	}
	return out
}

// intValue reads an integer literal, including a negated one: -1 is the
// tree's spelling of "unlimited" and is a UnaryExpr, not a BasicLit. A reader
// that handled only BasicLit would silently drop every unlimited field and
// then find nothing to disagree with.
func intValue(e ast.Expr) (int, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.INT {
			return 0, false
		}
		n, err := strconv.Atoi(v.Value)
		return n, err == nil
	case *ast.UnaryExpr:
		if v.Op != token.SUB {
			return 0, false
		}
		n, ok := intValue(v.X)
		return -n, ok
	default:
		return 0, false
	}
}

// TestTheTierLimitsParserWorks is the positive control on the parser above. Its
// output is the whole subject of the reconciliation that follows, and an empty
// map would make every comparison there pass.
func TestTheTierLimitsParserWorks(t *testing.T) {
	limits := tierLimits(t)
	for _, tier := range []string{"CommunityLimits", "EvaluationLimits", "EnterpriseLimits"} {
		fields, ok := limits[tier]
		if !ok {
			t.Fatalf("%s was not found in %s; the parser is looking at the wrong shape",
				tier, tierLimitsPath)
		}
		if len(fields) < 10 {
			t.Fatalf("%s parsed to %d fields, which is far fewer than it declares",
				tier, len(fields))
		}
	}
	// The three tiers must actually differ, or the parser is reading one
	// literal three times.
	if limits["CommunityLimits"]["TenantPolicies"] == limits["EvaluationLimits"]["TenantPolicies"] {
		t.Fatal("Community and Evaluation parsed to the same TenantPolicies; the parser " +
			"is not distinguishing the three literals")
	}
	// And the negative-literal path must have produced a negative number
	// somewhere, or "unlimited" was silently dropped.
	var sawNegative bool
	for _, v := range limits["EnterpriseLimits"] {
		if v < 0 {
			sawNegative = true
		}
	}
	if !sawNegative {
		t.Fatal("no negative value was parsed out of EnterpriseLimits; -1 is how this " +
			"tree spells unlimited, so the UnaryExpr path is not working")
	}
}

// matrixLimitRow extracts one row of the matrix's Three-Tier Licensing Model
// table as its cells.
func matrixLimitRow(t *testing.T, src, tier string) []string {
	t.Helper()
	for _, line := range strings.Split(src, "\n") {
		if !strings.HasPrefix(line, "| **"+tier+"**") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		return cells
	}
	t.Fatalf("no row for %q in the matrix's licensing table; the table has moved or been "+
		"renamed and this reconciliation is reading nothing", tier)
	return nil
}

// normaliseLimit turns a matrix cell into the integer the code holds.
func normaliseLimit(cell string) (int, bool) {
	c := strings.ToLower(strings.TrimSpace(cell))
	if c == "unlimited" {
		return -1, true
	}
	fields := strings.Fields(c)
	if len(fields) == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, false
	}
	return n, true
}

// TestTheMatrixLicensingTableAgreesWithTheExecutableLimits is #3590's
// "reconcile the matrix against executable limits" in its literal form.
//
// Both sides are read mechanically: the matrix row from its markdown table, the
// limits from the Go composite literals. Neither is retyped into this test, so
// this cannot pass by agreeing with a transcription of itself.
func TestTheMatrixLicensingTableAgreesWithTheExecutableLimits(t *testing.T) {
	src := readMatrix(t)
	limits := tierLimits(t)

	// Column index in the matrix's licensing table -> TierLimits field.
	// Index 0 is the tier name and 1 is "License Required", which is not a
	// numeric limit.
	columns := map[int]string{
		2:  "TenantPolicies",
		3:  "OrgPolicies",
		4:  "CustomPolicyConnectors",
		5:  "AuditRetentionDays",
		6:  "MaxLLMProviders",
		7:  "MaxExecutionHistory",
		8:  "MaxConcurrentExec",
		9:  "MaxPlans",
		10: "MaxVersionsPerPlan",
	}
	var compared int
	for tier, varName := range map[string]string{
		"Community":  "CommunityLimits",
		"Evaluation": "EvaluationLimits",
		"Enterprise": "EnterpriseLimits",
	} {
		cells := matrixLimitRow(t, src, tier)
		for idx, field := range columns {
			if idx >= len(cells) {
				t.Errorf("%s: the matrix row has %d cells, so column %d (%s) is missing",
					tier, len(cells), idx, field)
				continue
			}
			want, ok := limits[varName][field]
			if !ok {
				t.Errorf("%s: %s declares no %s", tier, tierLimitsPath, field)
				continue
			}
			got, ok := normaliseLimit(cells[idx])
			if !ok {
				t.Errorf("%s: the matrix cell for %s reads %q, which is not a number or "+
					"\"Unlimited\"", tier, field, cells[idx])
				continue
			}
			compared++
			if got != want {
				t.Errorf("MATRIX/CODE DISAGREEMENT — %s %s: the matrix says %q, "+
					"%s says %d", tier, field, cells[idx], tierLimitsPath, want)
			}
		}
	}
	if compared < 20 {
		t.Fatalf("only %d cell(s) were compared; the reconciliation is reading almost "+
			"nothing and its silence means nothing", compared)
	}
	t.Logf("reconciled %d matrix cells against %s", compared, tierLimitsPath)
}

// TestEveryLicenseGateNamesARealTierLimitsField stops the registry inventing an
// entitlement lever. A capability that says it is capped by "MaxWidgets" is
// making an unfalsifiable claim, and "limited" scores rest on these names.
func TestEveryLicenseGateNamesARealTierLimitsField(t *testing.T) {
	limits := tierLimits(t)
	known := map[string]bool{}
	for _, fields := range limits {
		for f := range fields {
			known[f] = true
		}
	}
	// Boolean gates are declared in the struct but carry no integer value, so
	// they are absent from the parsed maps. Read the struct's own field list.
	for _, f := range tierLimitsStructFields(t) {
		known[f] = true
	}
	if len(known) < 15 {
		t.Fatalf("only %d TierLimits field names were found; the set this test checks "+
			"against is too small to catch anything", len(known))
	}
	var checked int
	for _, e := range Load().Entries {
		for _, gate := range e.LicenseGate {
			checked++
			if !known[gate] {
				t.Errorf("%s names license_gate %q, which is not a field of TierLimits in "+
					"%s", e.ID, gate, tierLimitsPath)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no capability names a license_gate, so this test asserted nothing")
	}
	t.Logf("checked %d license_gate reference(s) against %d TierLimits fields",
		checked, len(known))
}

// tierLimitsStructFields returns the field names of the TierLimits struct.
func tierLimitsStructFields(t *testing.T) []string {
	t.Helper()
	full := filepath.Join(repoRoot(t), tierLimitsPath)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, full, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", tierLimitsPath, err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "TierLimits" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, field := range st.Fields.List {
			for _, name := range field.Names {
				out = append(out, name.Name)
			}
		}
		return false
	})
	if len(out) == 0 {
		t.Fatalf("no TierLimits struct found in %s", tierLimitsPath)
	}
	return out
}
