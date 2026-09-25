// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package anchoredenforcer

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// THE COUNTER'S VERDICT LABELS HAVE ONE HOME, AND THIS KEEPS THEM THERE
// (#4249 row 5666277893).
//
// axonflow_decision_enforce_decisions_total is labelled by verdict, and the
// four labels are VerdictAllow, VerdictDeny, VerdictNeedsApproval and
// VerdictUnavailable in this package. The agent re-exports the first three
// (agent.VerdictAllow = anchoredenforcer.VerdictAllow, and so on). A label
// spelled as a literal at a call site is a second home: a rename here would
// leave it behind, and the series would split in two with nothing failing.
//
// The guard is keyed on the counter calls, not on the strings, because
// "allow" and "deny" are also the workflow gate's Action and the audit
// vocabulary's, which this family does not touch. For every call to
// RecordEnforcement( or the agent's recordAnchoredEnforcement( in the agent's
// and the orchestrator's non-test sources, the verdict argument must be one of
// the four constant names, or one of the INDIRECT SITES below. An indirect site
// passes a value, and the guard traces that value back through each function
// that produces it: every return, and every assignment that feeds it, must be
// one of the four constant names, the pass-through parameter, or another traced
// function. Anything else reds, naming its file and line.
//
// THE INDIRECT SITES, AND WHERE EACH VALUE COMES FROM:
//
//   - agent/decision_enforcing_seam.go, recordAnchoredEnforcement: `verdict` is
//     its own parameter, the wrapper forwarding what its callers pass, and
//     every caller is held to this rule.
//   - agent/decision_handler.go, the decide handler: `verdict` is assigned from
//     enforced.verdict (set only as below), from applyObligationGates, and from
//     VerdictNeedsApproval.
//   - agent/gateway_handlers.go, handlePolicyPreCheck: `preCheckVerdict(response)`,
//     which returns VerdictDeny or VerdictAllow.
//   - agent/mcp_response_enforcing_seam.go, enforceMCPResponse: `verdict`,
//     anchoredResponse's second result, which is VerdictDeny or VerdictAllow,
//     or "" beside a non-nil error (the caller records nothing then).
//
// Each site is keyed by its FILE AND FUNCTION, so the same expression in any
// other function is not an indirect site and reds. A function that passes its
// own `verdict` to a counter call is held to the rule for every assignment to
// it, including a default it gives an empty parameter. A traced producer's
// named verdict result is held to the rule at every assignment.
//
// The fields: every `<x>.verdict = ...` in the agent (the decide seam's
// enforced result, decision_enforcing_seam.go and approval_hold_enterprise.go)
// must assign one of the constants.
//
// THE COUNTER IS REACHED ONLY BY CALLING IT. The CounterVec (Decisions) is
// named only inside RecordEnforcement and the package's init; either counter
// function taken as a value reds (counterHandleViolations).
//
// A FLOOR PER DIRECTORY: at least 26 counter calls with a constant label under
// platform/agent and 32 under platform/orchestrator, the census at this
// change, and all four indirect sites, so a parser that finds nothing, or a
// directory that moved, cannot pass. ee/ is read and holds no counter call, so
// it has no floor.
//
// NAME-ONLY LIMITS, STATED (#4249 row 5801272698, #4408 round 2 F5): a local that
// shadows a constant's name (VerdictAllow := "allowed") or a parameter named
// VerdictUnavailable is read as the constant, because this guard reads syntax,
// not types. Neither exists in the tree; a types-based pass would close them.
//
// WHAT IT READS, AND ITS LIMIT. It reads every non-test .go file under
// platform/ and ee/, so a counter call added in any package is seen. It skips
// directories named testdata or node_modules or starting with a dot, and it
// does not follow a symlinked directory, whose files are therefore neither
// read nor counted. It reads
// SYNTAX, not types: a constant is accepted only as anchoredenforcer.VerdictX,
// or as the agent's bare VerdictX, whose definitions in the agent must
// themselves be `= anchoredenforcer.VerdictX`; the decide seam's result is
// recognised by its type name (requestPassEnforcement) in composite literals
// and by its variable names (enforced, allowed, out) in reads. A future
// producer shaped differently reds until this guard is taught it, which fails
// closed.

var verdictLabelNames = map[string]bool{
	"VerdictAllow": true, "VerdictDeny": true, "VerdictNeedsApproval": true, "VerdictUnavailable": true,
}

// indirectVerdictSites is file (relative to platform/) and the rendered
// verdict argument: the four sites that pass a value, each traced below.
var indirectVerdictSites = map[string]bool{
	"platform/agent/decision_enforcing_seam.go|recordAnchoredEnforcement|verdict":       true, // the wrapper's own parameter
	"platform/agent/decision_handler.go|handleDecide|verdict":                           true, // traced by its assignments
	"platform/agent/gateway_handlers.go|handlePolicyPreCheck|preCheckVerdict(response)": true, // preCheckVerdict's returns
	"platform/agent/mcp_response_enforcing_seam.go|enforceMCPResponse|verdict":          true, // anchoredResponse's second result, and its assignments
}

// resultVars are the variable names the decide seam's result
// (requestPassEnforcement) is read through where a verdict is taken from it.
var resultVars = map[string]bool{"enforced": true, "allowed": true, "out": true}

// tracedVerdictFuncs are the functions that produce a verdict an indirect site
// passes, and which of their results is the verdict.
var tracedVerdictFuncs = map[string]int{
	"preCheckVerdict":                0,
	"anchoredResponse":               1,
	"applyObligationGates":           0,
	"applyPEPCapabilityRefusal":      0,
	"applySeamCapabilityObligations": 0,
}

// minConstantLabelSites is, per package directory, the counter calls whose
// verdict is a constant: the census at this change (26 in the agent, 32 in the
// orchestrator, 58 in all). ee/ holds no counter call, so it has no floor; a
// counter call added there is still read and held to the rule.
var minConstantLabelSites = map[string]int{
	"platform/agent":        26,
	"platform/orchestrator": 32,
}

// mirrorMinConstantLabelSites is the same census on a community-mirror
// checkout, where the sync deletes every enterprise-tagged file: five of the
// agent's 26 constant-verdict counter calls are in such files, so 21 remain,
// and every orchestrator call ships. A walk that lost a directory still reds
// on either tree, because each floor is the count that tree carries.
var mirrorMinConstantLabelSites = map[string]int{
	"platform/agent":        21,
	"platform/orchestrator": 32,
}

// constantLabelFloors returns the floors for the tree at repoRoot: the
// enterprise census where ee/ is present, the mirror's where it is not.
func constantLabelFloors(repoRoot string) map[string]int {
	if _, err := os.Lstat(filepath.Join(repoRoot, "ee")); os.IsNotExist(err) {
		return mirrorMinConstantLabelSites
	}
	return minConstantLabelSites
}

const wantIndirectSites = 4

type parsedSource struct {
	fset  *token.FileSet
	files map[string]*ast.File // relative to the repository root, slash-separated
}

// parseVerdictSources parses every non-test .go file under each root (relative
// to repoRoot), skipping testdata and node_modules.
func parseVerdictSources(t *testing.T, repoRoot string, roots ...string) parsedSource {
	t.Helper()
	src := parsedSource{fset: token.NewFileSet(), files: map[string]*ast.File{}}
	for _, root := range roots {
		if root == "ee" {
			if _, err := os.Lstat(filepath.Join(repoRoot, root)); os.IsNotExist(err) {
				// A community-mirror checkout: the sync strips ee/ whole, and
				// an absent ee/ is what a mirror checkout IS, so there is no
				// enterprise tree whose ee/ could have gone missing. ee/ holds
				// no counter call today (minConstantLabelSites has no floor
				// for it), so the guard reads the same sites here as on the
				// enterprise tree, where ee/ is walked and held to the rule.
				continue
			}
		}
		err := filepath.WalkDir(filepath.Join(repoRoot, root), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if n := d.Name(); n == "testdata" || n == "node_modules" || strings.HasPrefix(n, ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(src.fset, path, nil, 0)
			if perr != nil {
				return fmt.Errorf("parse %s: %w", path, perr)
			}
			rel, _ := filepath.Rel(repoRoot, path)
			src.files[filepath.ToSlash(rel)] = f
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return src
}

func renderExpr(fset *token.FileSet, e ast.Expr) string {
	var b bytes.Buffer
	_ = printer.Fprint(&b, fset, e)
	return b.String()
}

// isVerdictConst accepts anchoredenforcer.VerdictX anywhere, and the agent's
// bare VerdictX re-exports in the agent package only.
func isVerdictConst(rel string, e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return verdictLabelNames[x.Name] && (strings.HasPrefix(rel, "platform/agent/") && !strings.Contains(strings.TrimPrefix(rel, "platform/agent/"), "/") ||
			strings.HasPrefix(rel, "platform/shared/anchoredenforcer/"))
	case *ast.SelectorExpr:
		pkg, ok := x.X.(*ast.Ident)
		return ok && pkg.Name == homeLocalName(rel) && verdictLabelNames[x.Sel.Name]
	}
	return false
}

// homeImportPath is this package's import path.
const homeImportPath = "axonflow/platform/shared/anchoredenforcer"

// homeAliases is, per file, the local name the file imports this package
// under ("" when it does not import it). It is filled from each file's import
// table before the guard reads the file, so an aliased import
// (ae "axonflow/platform/shared/anchoredenforcer") is read as the package
// itself: a guard keyed on the package's NAME would not see ae.Decisions.
var homeAliases = map[string]string{}

// homeLocalName is the name rel refers to this package by: its alias, or the
// package name when the import is unaliased or absent.
func homeLocalName(rel string) string {
	if a := homeAliases[rel]; a != "" {
		return a
	}
	return "anchoredenforcer"
}

// readHomeImport records rel's local name for this package, and reds a
// dot-import of it: a dot-import makes Decisions and RecordEnforcement bare
// names in another package, where nothing distinguishes them.
func readHomeImport(fset *token.FileSet, rel string, f *ast.File) []string {
	delete(homeAliases, rel)
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != homeImportPath || imp.Name == nil {
			continue
		}
		if imp.Name.Name == "." {
			p := fset.Position(imp.Pos())
			return []string{filepath.Base(p.Filename) + ":" + strconv.Itoa(p.Line) + ": a dot-import of anchoredenforcer; import it by name, so its counter and CounterVec stay visible to this guard"}
		}
		homeAliases[rel] = imp.Name.Name
	}
	return nil
}

// funcUnit is one function body the guard reads on its own: a declared
// function, or a function literal anywhere in a file (a package-level
// `var hook = func(...)`, or a closure inside a function). A literal is its
// own unit: an allow-listed site is keyed by its DECLARED function, so a
// closure inside it is never that site, and its parameter is not the listed
// one.
type funcUnit struct {
	Name *ast.Ident
	Type *ast.FuncType
	Body *ast.BlockStmt
}

// functionUnits lists f's declared functions and every function literal in f.
func functionUnits(fset *token.FileSet, f *ast.File) []*funcUnit {
	var units []*funcUnit
	enclosing := "package"
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			enclosing = fn.Name.Name
			if fn.Body != nil {
				units = append(units, &funcUnit{Name: fn.Name, Type: fn.Type, Body: fn.Body})
			}
		} else {
			enclosing = "package"
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			if lit, ok := n.(*ast.FuncLit); ok {
				name := enclosing + ".func@" + strconv.Itoa(fset.Position(lit.Pos()).Line)
				units = append(units, &funcUnit{Name: &ast.Ident{Name: name, NamePos: lit.Pos()}, Type: lit.Type, Body: lit.Body})
			}
			return true
		})
	}
	return units
}

// inspectOwn is ast.Inspect over a unit's own body, not descending into a
// function literal inside it, which is its own unit.
func inspectOwn(body *ast.BlockStmt, visit func(ast.Node) bool) {
	ast.Inspect(body, func(n ast.Node) bool {
		if _, lit := n.(*ast.FuncLit); lit {
			return false
		}
		return visit(n)
	})
}

func calleeName(c *ast.CallExpr) string {
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// isResultVerdict is a read of the decide seam's result's verdict:
// enforced.verdict, allowed.verdict or out.verdict.
func isResultVerdict(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "verdict" {
		return false
	}
	base, ok := sel.X.(*ast.Ident)
	return ok && resultVars[base.Name]
}

// verdictParamIndex is the position of the parameter named verdict, or -1.
func verdictParamIndex(typ *ast.FuncType) int {
	i := 0
	for _, f := range typ.Params.List {
		if len(f.Names) == 0 {
			i++
			continue
		}
		for _, n := range f.Names {
			if n.Name == "verdict" {
				return i
			}
			i++
		}
	}
	return -1
}

// verdictLabelViolations is the guard, over already-parsed sources, so the
// plants below can run it over a planted tree.
func verdictLabelViolations(src parsedSource) (violations []string, constantSites map[string]int, indirectSeen map[string]bool) {
	indirectSeen = map[string]bool{}
	constantSites = map[string]int{}
	at := func(n ast.Node) string {
		p := src.fset.Position(n.Pos())
		return filepath.Base(p.Filename) + ":" + strconv.Itoa(p.Line)
	}
	names := make([]string, 0, len(src.files))
	for rel := range src.files {
		names = append(names, rel)
	}
	sort.Strings(names)

	// The traced producers, by name, with the position of their verdict
	// parameter, found wherever they are declared.
	tracedParam := map[string]int{}
	tracedSeen := map[string]bool{}
	for _, rel := range names {
		for _, decl := range src.files[rel].Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok {
				if _, traced := tracedVerdictFuncs[fn.Name.Name]; traced {
					tracedSeen[fn.Name.Name] = true
					tracedParam[fn.Name.Name] = verdictParamIndex(fn.Type)
				}
			}
		}
	}
	isTracedCall := func(e ast.Expr) bool {
		c, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		_, traced := tracedVerdictFuncs[calleeName(c)]
		return traced
	}

	for _, rel := range names {
		violations = append(violations, readHomeImport(src.fset, rel, src.files[rel])...)
	}
	for _, rel := range names {
		f := src.files[rel]
		agentFile := strings.HasPrefix(rel, "platform/agent/")
		for _, fn := range functionUnits(src.fset, f) {
			idx, traced := tracedVerdictFuncs[fn.Name.Name]
			// resultName is a traced producer's NAMED verdict result, whose
			// assignments are its returns.
			resultName := ""
			if traced {
				resultName = namedResult(fn.Type, idx)
			}
			passesVerdict := false
			inspectOwn(fn.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok && (calleeName(c) == "recordAnchoredEnforcement" || calleeName(c) == "RecordEnforcement") && len(c.Args) == 4 {
					if id, ok := c.Args[2].(*ast.Ident); ok && id.Name == "verdict" {
						passesVerdict = true
					}
				}
				return true
			})
			// okVerdict is what may be assigned to, returned as, or passed as a
			// verdict inside this function.
			okVerdict := func(e ast.Expr, allowEmpty bool) bool {
				if isVerdictConst(rel, e) || isTracedCall(e) || isResultVerdict(e) {
					return true
				}
				if id, isID := e.(*ast.Ident); isID && id.Name == "verdict" {
					return verdictParamIndex(fn.Type) >= 0 || passesVerdict || traced
				}
				if id, isID := e.(*ast.Ident); isID && resultName != "" && id.Name == resultName {
					return true
				}
				if lit, isLit := e.(*ast.BasicLit); isLit {
					return allowEmpty && lit.Value == `""`
				}
				return false
			}
			inspectOwn(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					name := calleeName(x)
					if (name == "RecordEnforcement" || name == "recordAnchoredEnforcement") && len(x.Args) == 4 {
						arg := x.Args[2]
						if isVerdictConst(rel, arg) {
							constantSites[filepath.ToSlash(filepath.Dir(rel))]++
							break
						}
						expr := renderExpr(src.fset, arg)
						key := rel + "|" + fn.Name.Name + "|" + expr
						if indirectVerdictSites[key] {
							indirectSeen[key] = true
							break
						}
						violations = append(violations, at(x)+": the counter's verdict is "+expr+
							"; name one of anchoredenforcer.VerdictAllow/Deny/NeedsApproval/Unavailable (or add a traced indirect site to this guard)")
					}
					// A call to a traced producer passes a verdict in: that
					// argument is held to the same rule.
					if pi, isTraced := tracedParam[name]; isTraced && pi >= 0 && pi < len(x.Args) {
						if !okVerdict(x.Args[pi], false) {
							violations = append(violations, at(x)+": "+name+" is passed the verdict "+renderExpr(src.fset, x.Args[pi])+", not a verdict constant")
						}
					}
				case *ast.ReturnStmt:
					if traced && len(x.Results) > idx {
						errBeside := fn.Name.Name == "anchoredResponse" && !isNilIdent(x.Results[len(x.Results)-1])
						if !okVerdict(x.Results[idx], errBeside) {
							violations = append(violations, at(x)+": "+fn.Name.Name+" returns the verdict "+renderExpr(src.fset, x.Results[idx])+", not a verdict constant")
						}
					}
				case *ast.AssignStmt:
					for i, lhs := range x.Lhs {
						var rhs ast.Expr
						switch {
						case len(x.Rhs) == len(x.Lhs):
							rhs = x.Rhs[i]
						case len(x.Rhs) == 1:
							rhs = x.Rhs[0] // a multi-value call: the call is what is checked
						}
						switch l := lhs.(type) {
						case *ast.SelectorExpr:
							// Every write to a verdict field in the agent is a
							// constant (or a traced producer's result).
							if agentFile && l.Sel.Name == "verdict" && (rhs == nil || !(isVerdictConst(rel, rhs) || isTracedCall(rhs))) {
								violations = append(violations, at(x)+": "+renderExpr(src.fset, lhs)+" is assigned "+renderExpr(src.fset, rhs)+", not a verdict constant")
							}
						case *ast.Ident:
							if l.Name == "verdict" && (traced || passesVerdict) && (rhs == nil || !okVerdict(rhs, false)) {
								violations = append(violations, at(x)+": "+fn.Name.Name+" assigns verdict "+renderExpr(src.fset, rhs)+", not a verdict constant or a traced producer")
							}
							if resultName != "" && l.Name == resultName && (rhs == nil || !okVerdict(rhs, false)) {
								violations = append(violations, at(x)+": "+fn.Name.Name+" assigns its verdict result "+resultName+" "+renderExpr(src.fset, rhs)+", not a verdict constant or a traced producer")
							}
						}
					}
				case *ast.ValueSpec:
					for i, nm := range x.Names {
						if nm.Name == "verdict" && (traced || passesVerdict) && i < len(x.Values) && !okVerdict(x.Values[i], false) {
							violations = append(violations, at(x)+": "+fn.Name.Name+" declares verdict "+renderExpr(src.fset, x.Values[i])+", not a verdict constant or a traced producer")
						}
					}
				case *ast.CompositeLit:
					// The decide seam's result built with a verdict.
					if id, isID := x.Type.(*ast.Ident); isID && id.Name == "requestPassEnforcement" {
						for _, el := range x.Elts {
							if kv, isKV := el.(*ast.KeyValueExpr); isKV {
								if k, isK := kv.Key.(*ast.Ident); isK && k.Name == "verdict" && !isVerdictConst(rel, kv.Value) {
									violations = append(violations, at(x)+": requestPassEnforcement is built with verdict "+renderExpr(src.fset, kv.Value)+", not a verdict constant")
								}
							}
						}
					}
				}
				return true
			})
		}
		// The agent's bare VerdictX are re-exports of the home, never values,
		// in whichever agent file declares one.
		if agentFile && !strings.Contains(strings.TrimPrefix(rel, "platform/agent/"), "/") {
			for _, decl := range f.Decls {
				gd, isGen := decl.(*ast.GenDecl)
				if !isGen || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
					continue
				}
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, nm := range vs.Names {
						if verdictLabelNames[nm.Name] && i < len(vs.Values) {
							sel, isSel := vs.Values[i].(*ast.SelectorExpr)
							if !isSel || renderExpr(src.fset, sel) != "anchoredenforcer."+nm.Name {
								violations = append(violations, at(vs)+": the agent's "+nm.Name+" is "+renderExpr(src.fset, vs.Values[i])+", not a re-export of anchoredenforcer."+nm.Name)
							}
						}
					}
				}
			}
		}
		violations = append(violations, counterHandleViolations(src.fset, rel, f)...)
	}
	for name := range tracedVerdictFuncs {
		if !tracedSeen[name] {
			violations = append(violations, "the traced verdict producer "+name+" was not found; the guard's trace no longer matches the tree")
		}
	}
	return violations, constantSites, indirectSeen
}

// namedResult is the name of fn's result at idx, "" when it is unnamed.
func namedResult(typ *ast.FuncType, idx int) string {
	if typ.Results == nil {
		return ""
	}
	i := 0
	for _, f := range typ.Results.List {
		if len(f.Names) == 0 {
			i++
			continue
		}
		for _, n := range f.Names {
			if i == idx {
				return n.Name
			}
			i++
		}
	}
	return ""
}

// counterHandleViolations reds on every way to reach the counter other than a
// CALL to RecordEnforcement or the agent's recordAnchoredEnforcement:
//
//   - the CounterVec itself (Decisions). It is exported, so
//     Decisions.WithLabelValues(..., "deny", ...).Inc() would count a label the
//     call rule never sees. Only RecordEnforcement and the package's init (the
//     registration) name it.
//   - either counter function taken as a VALUE (var record = RecordEnforcement),
//     whose calls the call rule would not recognise by name.
func counterHandleViolations(fset *token.FileSet, rel string, f *ast.File) []string {
	var out []string
	at := func(n ast.Node) string {
		p := fset.Position(n.Pos())
		return filepath.Base(p.Filename) + ":" + strconv.Itoa(p.Line)
	}
	home := strings.HasPrefix(rel, "platform/shared/anchoredenforcer/") && !strings.Contains(strings.TrimPrefix(rel, "platform/shared/anchoredenforcer/"), "/")
	agent := strings.HasPrefix(rel, "platform/agent/") && !strings.Contains(strings.TrimPrefix(rel, "platform/agent/"), "/")
	called := map[ast.Node]bool{} // the Fun of every call
	selected := map[*ast.Ident]bool{}
	declared := map[*ast.Ident]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			called[x.Fun] = true
		case *ast.SelectorExpr:
			selected[x.Sel] = true
		case *ast.FuncDecl:
			declared[x.Name] = true
		case *ast.ValueSpec:
			for _, nm := range x.Names {
				declared[nm] = true
			}
		}
		return true
	})
	for _, decl := range f.Decls {
		inRecorder := false
		if fn, ok := decl.(*ast.FuncDecl); ok && home && fn.Recv == nil && (fn.Name.Name == "RecordEnforcement" || fn.Name.Name == "init" && filepath.Base(rel) == "enforcer.go") {
			inRecorder = true
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				pkg, ok := x.X.(*ast.Ident)
				if !ok || pkg.Name != homeLocalName(rel) {
					return true
				}
				switch x.Sel.Name {
				case "Decisions":
					out = append(out, at(x)+": anchoredenforcer.Decisions is named outside RecordEnforcement; count through RecordEnforcement, whose verdict this guard checks")
				case "RecordEnforcement":
					if !called[x] {
						out = append(out, at(x)+": anchoredenforcer.RecordEnforcement is taken as a value; call it, so its verdict is checked")
					}
				}
			case *ast.Ident:
				if selected[x] || declared[x] {
					return true
				}
				switch {
				case home && x.Name == "Decisions" && !inRecorder:
					out = append(out, at(x)+": Decisions is named outside RecordEnforcement; count through RecordEnforcement, whose verdict this guard checks")
				case home && x.Name == "RecordEnforcement" && !called[x]:
					out = append(out, at(x)+": RecordEnforcement is taken as a value; call it, so its verdict is checked")
				case agent && x.Name == "recordAnchoredEnforcement" && !called[x]:
					out = append(out, at(x)+": recordAnchoredEnforcement is taken as a value; call it, so its verdict is checked")
				}
			}
			return true
		})
	}
	return out
}

func isNilIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "nil"
}

func TestTheCounterVerdictIsAlwaysAHomeConstant(t *testing.T) {
	src := parseVerdictSources(t, filepath.Join("..", "..", ".."), "platform", "ee")
	violations, constantSites, indirectSeen := verdictLabelViolations(src)
	for _, v := range violations {
		t.Error(v)
	}
	t.Logf("counter calls with a constant verdict, per directory: %v", constantSites)
	for dir, floor := range constantLabelFloors(filepath.Join("..", "..", "..")) {
		if constantSites[dir] < floor {
			t.Errorf("the guard saw %d counter calls with a constant verdict under %s/, want at least %d: it is not reading the tree it guards", constantSites[dir], dir, floor)
		}
	}
	if len(indirectSeen) != wantIndirectSites {
		var missing []string
		for k := range indirectVerdictSites {
			if !indirectSeen[k] {
				missing = append(missing, k)
			}
		}
		sort.Strings(missing)
		t.Errorf("the guard saw %d of the %d pinned indirect sites; not found: %v", len(indirectSeen), wantIndirectSites, missing)
	}
}

// TestTheVerdictLabelGuardRedsOnEachPlantedDefect runs the guard over the real
// sources with one defect planted in one file at a time, and requires each to
// red. A guard that has never failed has never been tested. The seven after the
// first six are the bypasses the lane's R3 found in the first version of this
// guard; the nine after those, and the G5 and lost-directory cells, are the
// ones master's round 1 on #4408 found in the second.
func TestTheVerdictLabelGuardRedsOnEachPlantedDefect(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..")
	for _, plant := range []struct {
		name, file, from, to, want string
	}{
		{"an existing site changed to a literal", "platform/orchestrator/wcp_enforcing_seam.go",
			"anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictAllow, reason)",
			`anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, "allow", reason)`,
			`the counter's verdict is "allow"`},
		{"a NEW literal at a new site", "platform/orchestrator/step_request_body_cap.go",
			"anchoredenforcer.RecordEnforcement(scope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictDeny, workflow_control.RequestTooLarge)",
			"anchoredenforcer.RecordEnforcement(scope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictDeny, workflow_control.RequestTooLarge)\n\tanchoredenforcer.RecordEnforcement(scope, anchoredenforcer.EngineAnchored, \"deny\", \"planted\")",
			`the counter's verdict is "deny"`},
		{"a literal returned by a traced producer", "platform/agent/gateway_handlers.go",
			"if !resp.Approved {\n\t\treturn VerdictDeny\n", "if !resp.Approved {\n\t\treturn \"deny\"\n",
			`preCheckVerdict returns the verdict "deny"`},
		{"a literal written to the decide seam's verdict field", "platform/agent/decision_enforcing_seam.go",
			"out.verdict = VerdictAllow", `out.verdict = "allow"`,
			`out.verdict is assigned "allow"`},
		{"a literal reassigned to a local verdict before the counter", "platform/agent/mcp_response_enforcing_seam.go",
			"recordAnchoredEnforcement(mcpResponseSeamScope, decisionEngineAnchored, verdict, reason)",
			"verdict = \"deny\"\n\trecordAnchoredEnforcement(mcpResponseSeamScope, decisionEngineAnchored, verdict, reason)",
			`assigns verdict "deny"`},
		{"a new variable at a site outside the allowlist", "platform/agent/run.go",
			"recordAnchoredEnforcement(proxyRequestSeamScope, proxyEnforced.engine, VerdictAllow, proxyReason)",
			"recordAnchoredEnforcement(proxyRequestSeamScope, proxyEnforced.engine, proxyVerdict, proxyReason)",
			"the counter's verdict is proxyVerdict"},
		{"a var-declared literal verdict before the counter", "platform/agent/mcp_response_enforcing_seam.go",
			"recordAnchoredEnforcement(mcpResponseSeamScope, decisionEngineAnchored, verdict, reason)",
			"var verdict = \"denied\"\n\trecordAnchoredEnforcement(mcpResponseSeamScope, decisionEngineAnchored, verdict, reason)",
			`declares verdict "denied"`},
		{"another struct's verdict field read into the decide verdict", "platform/agent/decision_handler.go",
			"verdict = VerdictNeedsApproval", "verdict = coworkDecided{}.verdict",
			`assigns verdict coworkDecided{}.verdict`},
		{"a literal passed in as a traced producer's verdict", "platform/agent/decision_handler.go",
			"allowed.verdict, allowed.reasons, allowed.obligations)", `"allowed", allowed.reasons, allowed.obligations)`,
			`applyObligationGates is passed the verdict "allowed"`},
		{"another package's VerdictX at a counter call", "platform/agent/run.go",
			"recordAnchoredEnforcement(proxyRequestSeamScope, proxyEnforced.engine, VerdictAllow, proxyReason)",
			"recordAnchoredEnforcement(proxyRequestSeamScope, proxyEnforced.engine, pep.VerdictAllow, proxyReason)",
			"the counter's verdict is pep.VerdictAllow"},
		{"the decide result built with a literal verdict", "platform/agent/decision_enforcing_seam.go",
			"out := requestPassEnforcement{engine: decisionEngineAnchored}", `out := requestPassEnforcement{engine: decisionEngineAnchored, verdict: "allowed"}`,
			`requestPassEnforcement is built with verdict "allowed"`},
		{"an indirect site copied into a new function", "platform/agent/decision_handler.go",
			"func handleDecide(w http.ResponseWriter, r *http.Request) {",
			"func plantedDecide(verdict string) {\n\trecordAnchoredEnforcement(decideSeamScope, \"\", verdict, \"\")\n}\n\nfunc handleDecide(w http.ResponseWriter, r *http.Request) {",
			"the counter's verdict is verdict"},
		{"a verdict field written from an untraced call", "platform/agent/decision_enforcing_seam.go",
			"out.verdict = VerdictAllow", "out.verdict, _ = plantedVerdict()",
			`out.verdict is assigned plantedVerdict()`},
		{"the agent's re-export turned into a literal", "platform/agent/decision_handler.go",
			"VerdictDeny          = anchoredenforcer.VerdictDeny", `VerdictDeny          = "deny"`,
			`the agent's VerdictDeny is "deny"`},
		// Round 1 of master's review (#4408) found six more, each written below
		// as that round planted it.
		{"the CounterVec counted directly (G1)", "platform/orchestrator/wcp_enforcing_seam.go",
			"anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictAllow, reason)",
			`anchoredenforcer.Decisions.WithLabelValues(wcpSeamScope.String(), anchoredenforcer.EngineAnchored, "allow", reason).Inc()`,
			"anchoredenforcer.Decisions is named outside RecordEnforcement"},
		{"a handle on the CounterVec in the agent (G1)", "platform/agent/decision_enforcing_seam.go",
			"func recordAnchoredEnforcement(scope legacycompile.EnforcementScope, engine, verdict, reason string) {",
			"var plantedDecisions = anchoredenforcer.Decisions\n\nfunc recordAnchoredEnforcement(scope legacycompile.EnforcementScope, engine, verdict, reason string) {",
			"anchoredenforcer.Decisions is named outside RecordEnforcement"},
		{"the CounterVec counted in its own package (G1)", "platform/shared/anchoredenforcer/enforcer.go",
			"func RecordEnforcement(scope legacycompile.EnforcementScope, engine, verdict, reason string) {",
			"func plantedCount() { Decisions.WithLabelValues(\"\", \"\", \"deny\", \"\").Inc() }\n\nfunc RecordEnforcement(scope legacycompile.EnforcementScope, engine, verdict, reason string) {",
			"Decisions is named outside RecordEnforcement"},
		{"RecordEnforcement taken as a value (G2)", "platform/orchestrator/wcp_enforcing_seam.go",
			"anchoredenforcer.RecordEnforcement(wcpSeamScope, anchoredenforcer.EngineAnchored, anchoredenforcer.VerdictAllow, reason)",
			"record := anchoredenforcer.RecordEnforcement\n\trecord(wcpSeamScope, anchoredenforcer.EngineAnchored, \"allow\", reason)",
			"anchoredenforcer.RecordEnforcement is taken as a value"},
		{"recordAnchoredEnforcement taken as a value (G2)", "platform/agent/decision_enforcing_seam.go",
			"func recordAnchoredEnforcement(scope legacycompile.EnforcementScope, engine, verdict, reason string) {",
			"var plantedRecord = recordAnchoredEnforcement\n\nfunc recordAnchoredEnforcement(scope legacycompile.EnforcementScope, engine, verdict, reason string) {",
			"recordAnchoredEnforcement is taken as a value"},
		{"a wrapper beside the MCP response site (G3)", "platform/agent/mcp_response_enforcing_seam.go",
			"func enforceMCPResponse(",
			"func plantedRecord(verdict string) {\n\trecordAnchoredEnforcement(mcpResponseSeamScope, decisionEngineAnchored, verdict, \"\")\n}\n\nfunc plantedCaller() { plantedRecord(\"deny\") }\n\nfunc enforceMCPResponse(",
			"the counter's verdict is verdict"},
		{"the pre-check expression in another function (G3)", "platform/agent/gateway_handlers.go",
			"func preCheckVerdict(resp PreCheckResponse) string {",
			"func plantedPreCheck(response PreCheckResponse) {\n\trecordAnchoredEnforcement(gatewayRequestSeamScope, \"\", preCheckVerdict(response), \"\")\n}\n\nfunc preCheckVerdict(resp PreCheckResponse) string {",
			"the counter's verdict is preCheckVerdict(response)"},
		{"a wrapper that defaults its own parameter (G4)", "platform/agent/decision_enforcing_seam.go",
			"func recordAnchoredEnforcement(scope legacycompile.EnforcementScope, engine, verdict, reason string) {\n",
			"func recordAnchoredEnforcement(scope legacycompile.EnforcementScope, engine, verdict, reason string) {\n\tif verdict == \"\" {\n\t\tverdict = \"unavailable\"\n\t}\n",
			`recordAnchoredEnforcement assigns verdict "unavailable"`},
		// Round 2 of master's review (#4408) found these, each written as that
		// round planted it (P15-P17).
		{"a counter call in a package-level func literal in the agent (F1, P15)", "platform/agent/decision_enforcing_seam.go",
			"func recordAnchoredEnforcement(scope legacycompile.EnforcementScope, engine, verdict, reason string) {",
			"var plantedHook = func(scope legacycompile.EnforcementScope) {\n\trecordAnchoredEnforcement(scope, \"\", \"deny\", \"\")\n}\n\nfunc recordAnchoredEnforcement(scope legacycompile.EnforcementScope, engine, verdict, reason string) {",
			`the counter's verdict is "deny"`},
		{"a counter call in a package-level func literal in the orchestrator (F1, P16)", "platform/orchestrator/wcp_enforcing_seam.go",
			"func stepGateApprovalExpired(",
			"var plantedHook = func() { anchoredenforcer.RecordEnforcement(wcpSeamScope, \"\", \"deny\", \"\") }\n\nfunc stepGateApprovalExpired(",
			`the counter's verdict is "deny"`},
		{"a closure inside an allow-listed function (F2, P17)", "platform/agent/mcp_response_enforcing_seam.go",
			"recordAnchoredEnforcement(mcpResponseSeamScope, decisionEngineAnchored, verdict, reason)",
			"plantedFn := func(verdict string) { recordAnchoredEnforcement(mcpResponseSeamScope, decisionEngineAnchored, verdict, reason) }\n\tplantedFn(\"deny\")\n\trecordAnchoredEnforcement(mcpResponseSeamScope, decisionEngineAnchored, verdict, reason)",
			"the counter's verdict is verdict"},
		{"a traced producer with a named result (G6)", "platform/agent/gateway_handlers.go",
			"func preCheckVerdict(resp PreCheckResponse) string {\n\tif !resp.Approved {\n\t\treturn VerdictDeny\n\t}\n\treturn VerdictAllow\n}",
			"func preCheckVerdict(resp PreCheckResponse) (v string) {\n\tv = \"deny\"\n\tif resp.Approved {\n\t\tv = VerdictAllow\n\t}\n\treturn\n}",
			`preCheckVerdict assigns its verdict result v "deny"`},
	} {
		t.Run(plant.name, func(t *testing.T) {
			src := parseVerdictSources(t, repoRoot, "platform", "ee")
			path := filepath.Join(repoRoot, plant.file)
			body, err := os.ReadFile(path) //nolint:gosec // the repo's own sources
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(body), plant.from) != 1 {
				t.Fatalf("the plant's anchor matches %d times in %s, want 1: the plant no longer tests anything", strings.Count(string(body), plant.from), plant.file)
			}
			planted, err := parser.ParseFile(src.fset, path, strings.Replace(string(body), plant.from, plant.to, 1), 0)
			if err != nil {
				t.Fatalf("the planted %s does not parse: %v", plant.file, err)
			}
			src.files[plant.file] = planted
			violations, _, _ := verdictLabelViolations(src)
			for _, v := range violations {
				if strings.Contains(v, plant.want) {
					return
				}
			}
			t.Fatalf("the guard did not red on the plant; want a violation containing %q, got %v", plant.want, violations)
		})
	}

	t.Run("a counter call in a subpackage is read", func(t *testing.T) {
		src := parseVerdictSources(t, repoRoot, "platform", "ee")
		planted, err := parser.ParseFile(src.fset, "planted.go", "package sub\nfunc f() { anchoredenforcer.RecordEnforcement(s, \"\", \"deny\", \"\") }\n", 0)
		if err != nil {
			t.Fatal(err)
		}
		src.files["platform/orchestrator/somesub/planted.go"] = planted
		violations, _, _ := verdictLabelViolations(src)
		for _, v := range violations {
			if strings.Contains(v, `the counter's verdict is "deny"`) {
				return
			}
		}
		t.Fatalf("a literal counter call in a subpackage was not seen: %v", violations)
	})

	t.Run("a VerdictX declared in another agent file is held to the re-export rule (G5)", func(t *testing.T) {
		src := parseVerdictSources(t, repoRoot, "platform", "ee")
		planted, err := parser.ParseFile(src.fset, "planted_verdicts.go", "package agent\nconst VerdictUnavailable = \"unavailable\"\n", 0)
		if err != nil {
			t.Fatal(err)
		}
		src.files["platform/agent/planted_verdicts.go"] = planted
		violations, _, _ := verdictLabelViolations(src)
		for _, v := range violations {
			if strings.Contains(v, `the agent's VerdictUnavailable is "unavailable"`) {
				return
			}
		}
		t.Fatalf("a literal VerdictX in a new agent file was not seen: %v", violations)
	})

	// A NEW FILE carrying the plant, parsed beside the real tree (F3, F4).
	for _, c := range []struct{ name, rel, src, want string }{
		{"the CounterVec under an import alias (F3, P03)", "platform/orchestrator/planted_alias.go",
			"package orchestrator\nimport ae \"axonflow/platform/shared/anchoredenforcer\"\nfunc plantedCount() { ae.Decisions.WithLabelValues(\"\", \"\", \"deny\", \"\").Inc() }\n",
			"anchoredenforcer.Decisions is named outside RecordEnforcement"},
		{"a dot-import of the package (F3, P04)", "platform/orchestrator/planted_dot.go",
			"package orchestrator\nimport . \"axonflow/platform/shared/anchoredenforcer\"\nfunc plantedCount() { Decisions.WithLabelValues(\"\", \"\", \"deny\", \"\").Inc() }\n",
			"a dot-import of anchoredenforcer"},
		{"RecordEnforcement taken as a value under an alias (F3, P21)", "platform/orchestrator/planted_alias_value.go",
			"package orchestrator\nimport ae \"axonflow/platform/shared/anchoredenforcer\"\nvar plantedRecord = ae.RecordEnforcement\n",
			"anchoredenforcer.RecordEnforcement is taken as a value"},
		{"a second init in the home package counting (F4, P09)", "platform/shared/anchoredenforcer/planted_init.go",
			"package anchoredenforcer\nfunc init() { Decisions.WithLabelValues(\"\", \"\", \"deny\", \"\").Inc() }\n",
			"Decisions is named outside RecordEnforcement"},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := parseVerdictSources(t, repoRoot, "platform", "ee")
			planted, err := parser.ParseFile(src.fset, filepath.Base(c.rel), c.src, 0)
			if err != nil {
				t.Fatal(err)
			}
			src.files[c.rel] = planted
			violations, _, _ := verdictLabelViolations(src)
			for _, v := range violations {
				if strings.Contains(v, c.want) {
					return
				}
			}
			t.Fatalf("the guard did not red on the plant; want a violation containing %q, got %v", c.want, violations)
		})
	}

	t.Run("a walk that lost one directory fails that directory's floor", func(t *testing.T) {
		floors := constantLabelFloors(repoRoot)
		for dir := range floors {
			src := parseVerdictSources(t, repoRoot, "platform", "ee")
			for rel := range src.files {
				if strings.HasPrefix(rel, dir+"/") {
					delete(src.files, rel)
				}
			}
			_, constantSites, _ := verdictLabelViolations(src)
			if constantSites[dir] >= floors[dir] {
				t.Errorf("a walk without %s/ still counted %d sites there", dir, constantSites[dir])
			}
			for other, floor := range floors {
				if other != dir && constantSites[other] < floor {
					t.Errorf("dropping %s/ moved %s/'s count to %d", dir, other, constantSites[other])
				}
			}
		}
	})

	t.Run("the floor catches a guard that reads nothing", func(t *testing.T) {
		_, constantSites, indirectSeen := verdictLabelViolations(parsedSource{fset: token.NewFileSet(), files: map[string]*ast.File{}})
		for dir, floor := range minConstantLabelSites {
			if constantSites[dir] >= floor {
				t.Fatalf("an empty tree satisfied the floor under %s/ (%d sites)", dir, constantSites[dir])
			}
		}
		if len(indirectSeen) == wantIndirectSites {
			t.Fatalf("an empty tree saw all %d indirect sites", len(indirectSeen))
		}
	})
}
