// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// loaderPath is the reader the three #3397 scan-drop models describe.
var loaderPath = filepath.Join("..", "..", "shared", "policy", "loader.go")

// scanModel is the shape of the three legacyScanDestinations* lists.
type scanModel = []struct {
	Column string
	GoType string
}

// The scan destination types this guard knows, in two closed lists (#4078).
// The first version listed only the types that cannot hold NULL and treated
// every other type as safe. So json.RawMessage, a []byte by kind that
// database/sql still refuses a NULL (convertAssignRows admits nil only into
// *any, *[]byte and *sql.RawBytes), read as nullable, and the runtime model's
// missing metadata passed. A type on neither list is now an error: someone has
// to check it against database/sql before the guard judges it.
var (
	nullableScanTypes = map[string]bool{
		"any": true, "[]byte": true, "sql.RawBytes": true,
	}
	nonNullableScanTypes = map[string]bool{
		"string": true, "bool": true, "time.Time": true, "json.RawMessage": true,
		"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
		"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
		"float32": true, "float64": true,
	}
)

// scanTypeHoldsNULL reports whether database/sql can scan a NULL into a
// destination of the given declared type, and whether the guard knows the type
// at all. A pointer or a sql.Null* holds NULL, and so do the three raw types.
func scanTypeHoldsNULL(typ string) (holds, known bool) {
	switch {
	case strings.HasPrefix(typ, "*"), strings.HasPrefix(typ, "sql.Null"), nullableScanTypes[typ]:
		return true, true
	case nonNullableScanTypes[typ]:
		return false, true
	}
	return false, false
}

// TestScanDropModelsMatchTheLoaderQueries derives each #3397 scan-drop model
// from the reader it describes and fails when the two part (#4078).
//
// A model entry says a NULL in that column fails the legacy reader's scan and
// the row is enforced nowhere. That is true exactly when the reader SELECTs the
// column WITHOUT a COALESCE and scans it into a destination that cannot hold
// NULL. The dynamic model was written from the SCHEMA - description and
// category are nullable columns - and never from the QUERY, which COALESCEs
// both, so it declared a loaded row unenforced. Reading the query and the scan
// closes that in both directions: a modelled column the reader COALESCEs,
// scans into a nullable type or does not select fails here, and so does a
// drop-capable destination nobody modelled.
func TestScanDropModelsMatchTheLoaderQueries(t *testing.T) {
	f := parseLoader(t)
	policyRow := structFieldTypes(t, f, "policyRow")
	dynamicRow := structFieldTypes(t, f, "DynamicPolicyRow")

	// RefreshDynamicPolicies picks one of two queries and scans with the
	// matching argument list; pair each query with the scan of its length.
	dynScans := scanFields(t, f, "RefreshDynamicPolicies")
	if len(dynScans) != 2 {
		t.Fatalf("RefreshDynamicPolicies makes %d rows.Scan calls, want 2 (with and without segment_id)", len(dynScans))
	}
	dynamic := func(query string) readerPair {
		sql := constString(t, f, query)
		cols, err := selectColumns(sql)
		if err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		n := len(cols)
		var hit [][]string
		for _, s := range dynScans {
			if len(s) == n {
				hit = append(hit, s)
			}
		}
		if len(hit) != 1 {
			t.Fatalf("%s selects %d columns and %d of RefreshDynamicPolicies' scans have that many destinations, want 1", query, n, len(hit))
		}
		return readerPair{query, sql, hit[0], dynamicRow}
	}
	only := func(fn string) []string {
		scans := scanFields(t, f, fn)
		if len(scans) != 1 {
			t.Fatalf("%s makes %d rows.Scan calls, want 1", fn, len(scans))
		}
		return scans[0]
	}

	cases := []struct {
		name  string
		model scanModel
		pairs []readerPair
	}{
		{"dynamic", legacyScanDestinationsDynamic, []readerPair{
			dynamic("dynamicPoliciesQueryWithSegment"),
			dynamic("dynamicPoliciesQueryWithoutSegment"),
		}},
		// The runtime model is the union of the two runtime readers, as its
		// own comment records.
		{"runtime", legacyScanDestinationsRuntime, []readerPair{
			{"loadFromDatabase", localQuery(t, f, "loadFromDatabase"), only("scopedPolicyRows"), policyRow},
			{"LoadSystemPolicies", localQuery(t, f, "LoadSystemPolicies"), only("LoadSystemPolicies"), policyRow},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			derived := map[string]string{}
			for _, p := range c.pairs {
				for col, typ := range dropDestinations(t, p) {
					derived[col] = typ
				}
			}
			model := map[string]string{}
			for _, d := range c.model {
				if _, dup := model[d.Column]; dup {
					t.Errorf("the model lists %s twice", d.Column)
				}
				model[d.Column] = d.GoType
			}
			for _, col := range sortedColumnNames(model) {
				got, ok := derived[col]
				switch {
				case !ok:
					t.Errorf("the model says a NULL %s drops the row, but no reader selects it bare into a non-nullable "+
						"destination (it is COALESCEd, scanned into a nullable type, or not selected); remove it", col)
				case got != model[col]:
					t.Errorf("the model scans %s as %s; the reader's destination is %s", col, model[col], got)
				}
			}
			for _, col := range sortedColumnNames(derived) {
				if _, ok := model[col]; !ok {
					t.Errorf("a reader selects %s without COALESCE into a %s, so a NULL there drops the row; "+
						"the model does not list it", col, derived[col])
				}
			}
		})
	}
}

// TestADynamicRowWithANullCoalescedColumnIsNotAScanDrop is the behaviour the
// model now describes (#4078): RefreshDynamicPolicies COALESCEs description and
// category, so a NULL in either loads, and a NULL priority - scanned bare into
// an int - is still the drop it always was.
func TestADynamicRowWithANullCoalescedColumnIsNotAScanDrop(t *testing.T) {
	for _, col := range []string{"description", "category"} {
		t.Run("NULL "+col, func(t *testing.T) {
			id := "dyn_null_" + col
			rep, err := Compile([]RawRow{dynamicRow(t, id, map[string]any{col: nil})}, testOptions())
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			rec := recordFor(t, rep, id)
			if rec.HasReason(ReasonLegacyScanDrop) {
				t.Fatalf("a NULL %s was declared a scan drop, but the loader COALESCEs it and the row reaches the cache: %+v", col, rec.Reasons)
			}
			if len(rec.Planes) == 0 {
				t.Fatalf("the row compiled to no plane at all, so the absence of a scan drop asserted nothing")
			}
		})
	}
	t.Run("NULL priority (control)", func(t *testing.T) {
		rep, err := Compile([]RawRow{dynamicRow(t, "dyn_null_priority", map[string]any{"priority": nil})}, testOptions())
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		rec := recordFor(t, rep, "dyn_null_priority")
		found := false
		for _, r := range rec.Reasons {
			if r.Code == ReasonLegacyScanDrop && strings.Contains(r.Detail, "priority (int)") {
				found = true
			}
		}
		if !found {
			t.Fatalf("a NULL priority, scanned bare into an int, must still drop the row: %+v", rec.Reasons)
		}
	})
}

// TestTheGuardRefusesWhatItCannotClassify pins the two refusals the guard's
// verdicts rest on (#4078). A SELECT item of a shape the parser does not prove
// is an error, never a guess, and so is a scan type on neither list. The first
// five shapes are the ones R3 planted against the first, lenient version, which
// read the spaced COALESCE as bare, the wrapped and the concatenated ones as
// coalesced, the NULL default as safe and the alias as the column. A literal in
// a column's place is refused as well.
func TestTheGuardRefusesWhatItCannotClassify(t *testing.T) {
	items := []struct {
		item      string
		wantErr   bool
		name      string
		coalesced bool
	}{
		{item: "COALESCE (category, 'general') AS category", name: "category", coalesced: true},
		{item: "lower(COALESCE(category, 'general')) AS category", wantErr: true},
		{item: "COALESCE(category, 'general') || suffix AS category", wantErr: true},
		{item: "COALESCE(priority, NULL) AS priority", name: "priority", coalesced: false},
		{item: "COALESCE(category, 'general') AS cat", name: "category", coalesced: true},
		{item: "COALESCE(metadata, '{}'::jsonb) AS metadata", name: "metadata", coalesced: true},
		{item: "sp.id::text AS id", name: "id"},
		{item: "created_at", name: "created_at"},
		{item: "now() AS created_at", wantErr: true},
		{item: "*", wantErr: true},
		{item: "NULL AS metadata", wantErr: true},
		{item: "CURRENT_TIMESTAMP AS created_at", wantErr: true},
	}
	for _, c := range items {
		got, err := selectColumns("SELECT " + c.item + " FROM t")
		switch {
		case c.wantErr && err == nil:
			t.Errorf("%q: parsed as %+v, want an error", c.item, got)
		case !c.wantErr && err != nil:
			t.Errorf("%q: %v", c.item, err)
		case !c.wantErr && (len(got) != 1 || got[0].name != c.name || got[0].coalesced != c.coalesced):
			t.Errorf("%q: got %+v, want {name:%s coalesced:%t}", c.item, got, c.name, c.coalesced)
		}
	}

	// The splitter honours quotes: a ')' inside a literal must not close the
	// COALESCE, or the comma after it stops splitting.
	if got, err := selectColumns("SELECT COALESCE(x, ')') AS x, y FROM t"); err != nil || len(got) != 2 || !got[0].coalesced || got[1].name != "y" {
		t.Errorf("a quoted paren broke the split: %+v %v", got, err)
	}
	// SELECT is a keyword, not a substring: a bare column list whose first
	// column contains "select" must not be cut inside it.
	if got, err := selectColumns("selected_at, name"); err != nil || len(got) != 2 || got[0].name != "selected_at" {
		t.Errorf("a bare column list was cut at a substring: %+v %v", got, err)
	}

	types := []struct {
		typ          string
		holds, known bool
	}{
		{"json.RawMessage", false, true},
		{"string", false, true},
		{"time.Time", false, true},
		{"sql.NullString", true, true},
		{"*int", true, true},
		{"[]byte", true, true},
		{"pq.StringArray", false, false},
		{"?", false, false},
	}
	for _, c := range types {
		if holds, known := scanTypeHoldsNULL(c.typ); holds != c.holds || known != c.known {
			t.Errorf("%s: holds=%t known=%t, want holds=%t known=%t", c.typ, holds, known, c.holds, c.known)
		}
	}
}

// TestEveryModelledScanColumnIsARequiredCaptureColumn pins why the scan-drop
// judge's absence test never decides alone (#4078). compileOne refuses a row
// that lacks a required column as capture_incomplete before any scan-drop
// verdict. So as long as every modelled column is required, an absent one never
// reaches nullScanDestinations, and a model column that is NOT required would
// be judged "absent, therefore dropped" on a capture that simply did not select
// it. A mutant that drops the judge's absence test survives for exactly this
// reason, and this test is what makes that survivor an equivalent one.
func TestEveryModelledScanColumnIsARequiredCaptureColumn(t *testing.T) {
	for _, c := range []struct {
		name, table string
		model       scanModel
	}{
		{"runtime", "static_policies", legacyScanDestinationsRuntime},
		{"dynamic", "dynamic_policies", legacyScanDestinationsDynamic},
	} {
		req, err := RequiredColumns(c.table)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		required := map[string]bool{}
		for _, col := range req {
			required[col] = true
		}
		for _, d := range c.model {
			if !required[d.Column] {
				t.Errorf("the %s scan-drop model lists %s, which RequiredColumns(%q) does not: a capture without it "+
					"would reach the judge and read as a scan drop instead of capture_incomplete", c.name, d.Column, c.table)
			}
		}
	}
}

type readerPair struct {
	what    string
	sql     string
	fields  []string
	rowType map[string]string
}

// selectedColumn is one SELECT item: the source column it reads, and whether a
// COALESCE with a non-NULL literal default wraps the whole item.
type selectedColumn struct {
	name      string
	coalesced bool
}

// dropDestinations returns the source columns one reader selects without
// COALESCE into a destination that cannot hold NULL, with that destination's
// type.
func dropDestinations(t *testing.T, p readerPair) map[string]string {
	t.Helper()
	cols, err := selectColumns(p.sql)
	if err != nil {
		t.Fatalf("%s: %v", p.what, err)
	}
	if len(cols) != len(p.fields) {
		t.Fatalf("%s: the SELECT names %d columns and the Scan fills %d destinations; a positional scan "+
			"that disagrees with its query is a defect of its own", p.what, len(cols), len(p.fields))
	}
	out := map[string]string{}
	for i, c := range cols {
		typ, ok := p.rowType[p.fields[i]]
		if !ok {
			t.Fatalf("%s: the Scan fills field %s, which its row type does not declare", p.what, p.fields[i])
		}
		holds, known := scanTypeHoldsNULL(typ)
		if !known {
			t.Fatalf("%s: the Scan fills %s, a %s, which this guard does not classify; check whether database/sql "+
				"can scan a NULL into it, then add it to nullableScanTypes or nonNullableScanTypes", p.what, p.fields[i], typ)
		}
		if !c.coalesced && !holds {
			out[c.name] = typ
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s yields no drop-capable destination, so this comparison would be vacuous", p.what)
	}
	return out
}

var (
	fromKeyword   = regexp.MustCompile(`(?i)\bFROM\b`)
	selectKeyword = regexp.MustCompile(`(?i)\bSELECT\b`)
	// A bare word that is a literal or a niladic function, not a column.
	// "NULL AS metadata" would otherwise read as a column named null, and the
	// guard would ask for metadata to leave the model when every row drops.
	sqlLiteralNames = map[string]bool{
		"null": true, "true": true, "false": true, "default": true,
		"current_timestamp": true, "current_date": true, "current_time": true,
		"localtime": true, "localtimestamp": true, "current_user": true, "session_user": true,
		"user": true, "system_user": true, "current_role": true, "current_catalog": true, "current_schema": true,
	}
	// A bare item: an optional table prefix, the column, an optional cast and
	// an optional alias.
	bareItem = regexp.MustCompile(`(?is)^(?:[a-z_][a-z0-9_]*\.)?([a-z_][a-z0-9_]*)(?:::[a-z_][a-z0-9_]*)?` +
		`(?:\s+AS\s+[a-z_][a-z0-9_]*)?$`)
	// A COALESCE item: the WHOLE item is one COALESCE over one column and one
	// literal default, optionally cast and aliased. Anything wrapping it or
	// following it is not this shape.
	coalesceItem = regexp.MustCompile(`(?is)^COALESCE\s*\(\s*(?:[a-z_][a-z0-9_]*\.)?([a-z_][a-z0-9_]*)\s*,\s*` +
		`('(?:[^']|'')*'(?:::[a-z_][a-z0-9_]*)?|-?[0-9]+(?:\.[0-9]+)?|true|false|null)\s*\)` +
		`(?:::[a-z_][a-z0-9_]*)?(?:\s+AS\s+[a-z_][a-z0-9_]*)?$`)
)

// selectColumns splits a SELECT list (or a bare column list) into its items
// and classifies each as a bare column or a whole-item COALESCE. Each is keyed
// on its SOURCE column, the name the capture and the models use, never the
// alias. An item of any other shape is an error, not a guess (#4078). A
// lenient reading would call "lower(COALESCE(c, 'x'))" or
// "COALESCE(c, 'x') || d" coalesced, or "COALESCE(c, NULL)" safe, and all
// three can still hand the scan a NULL.
func selectColumns(sql string) ([]selectedColumn, error) {
	body := sql
	if loc := selectKeyword.FindStringIndex(sql); loc != nil {
		body = sql[loc[1]:]
		if j := fromKeyword.FindStringIndex(body); j != nil {
			body = body[:j[0]]
		}
	}
	var items []string
	depth, inQuote, start := 0, false, 0
	for i, r := range body {
		switch {
		case r == '\'':
			inQuote = !inQuote
		case inQuote:
		case r == '(':
			depth++
		case r == ')':
			depth--
		case r == ',' && depth == 0:
			items = append(items, body[start:i])
			start = i + 1
		}
	}
	items = append(items, body[start:])
	var out []selectedColumn
	for _, raw := range items {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		if m := coalesceItem.FindStringSubmatch(item); m != nil {
			// A NULL default is no default: the item can still be NULL.
			out = append(out, selectedColumn{name: strings.ToLower(m[1]), coalesced: !strings.EqualFold(m[2], "null")})
			continue
		}
		if m := bareItem.FindStringSubmatch(item); m != nil && !sqlLiteralNames[strings.ToLower(m[1])] {
			out = append(out, selectedColumn{name: strings.ToLower(m[1])})
			continue
		}
		return nil, fmt.Errorf("select item %q is neither a bare column nor a whole-item COALESCE with a literal "+
			"default, so this guard cannot say whether it can be NULL; extend selectColumns with a shape it proves", item)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no select items parsed from %q", sql)
	}
	return out, nil
}

func parseLoader(t *testing.T) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), loaderPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", loaderPath, err)
	}
	return f
}

// constString evaluates a package-level string constant, following + and
// references to other constants.
func constString(t *testing.T, f *ast.File, name string) string {
	t.Helper()
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, s := range gd.Specs {
			vs := s.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if n.Name == name && i < len(vs.Values) {
					return evalString(t, f, vs.Values[i])
				}
			}
		}
	}
	t.Fatalf("%s declares no string constant %s", loaderPath, name)
	return ""
}

func evalString(t *testing.T, f *ast.File, e ast.Expr) string {
	t.Helper()
	switch x := e.(type) {
	case *ast.BasicLit:
		s, err := strconv.Unquote(x.Value)
		if err != nil {
			t.Fatalf("unquote %s: %v", x.Value, err)
		}
		return s
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			return evalString(t, f, x.X) + evalString(t, f, x.Y)
		}
	case *ast.Ident:
		return constString(t, f, x.Name)
	case *ast.ParenExpr:
		return evalString(t, f, x.X)
	}
	t.Fatalf("cannot evaluate a %T as a string constant", e)
	return ""
}

func funcDecl(t *testing.T, f *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == name {
			return fd
		}
	}
	t.Fatalf("%s declares no func %s", loaderPath, name)
	return nil
}

// localQuery returns the string literal a function assigns to its local query.
func localQuery(t *testing.T, f *ast.File, fn string) string {
	t.Helper()
	var out []string
	ast.Inspect(funcDecl(t, f, fn), func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name == "query" {
			if lit, ok := as.Rhs[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				out = append(out, evalString(t, f, lit))
			}
		}
		return true
	})
	if len(out) != 1 {
		t.Fatalf("func %s assigns a literal query %d time(s), want 1", fn, len(out))
	}
	return out[0]
}

// scanFields returns, for each rows.Scan call in fn, its destination fields in
// order.
func scanFields(t *testing.T, f *ast.File, fn string) [][]string {
	t.Helper()
	var out [][]string
	ast.Inspect(funcDecl(t, f, fn), func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Scan" {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "rows" {
			return true
		}
		var fields []string
		for _, a := range call.Args {
			u, ok := a.(*ast.UnaryExpr)
			if !ok || u.Op != token.AND {
				t.Fatalf("%s: a rows.Scan argument is not &row.Field", fn)
			}
			s, ok := u.X.(*ast.SelectorExpr)
			if !ok {
				t.Fatalf("%s: a rows.Scan argument is not &row.Field", fn)
			}
			fields = append(fields, s.Sel.Name)
		}
		out = append(out, fields)
		return true
	})
	if len(out) == 0 {
		t.Fatalf("func %s makes no rows.Scan call", fn)
	}
	return out
}

// structFieldTypes maps each field of a struct type to its type as written.
func structFieldTypes(t *testing.T, f *ast.File, typeName string) map[string]string {
	t.Helper()
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, s := range gd.Specs {
			ts := s.(*ast.TypeSpec)
			st, ok := ts.Type.(*ast.StructType)
			if !ok || ts.Name.Name != typeName {
				continue
			}
			out := map[string]string{}
			for _, fld := range st.Fields.List {
				for _, n := range fld.Names {
					out[n.Name] = typeString(fld.Type)
				}
			}
			return out
		}
	}
	t.Fatalf("%s declares no struct type %s", loaderPath, typeName)
	return nil
}

func typeString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return typeString(x.X) + "." + x.Sel.Name
	case *ast.StarExpr:
		return "*" + typeString(x.X)
	case *ast.ArrayType:
		return "[]" + typeString(x.Elt)
	}
	return "?"
}

func sortedColumnNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
