// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

// The scanner half of the #3878 comparison census. The inventory it is held
// against, and every assertion, are in principal_comparison_census_test.go;
// this file is only the machinery, kept apart so the inventory reads as a
// document rather than as data buried in a parser.
//
// # WHY THIS IS A TYPE-CHECKED WALK AND NOT A GREP
//
// The class it enumerates is "two principals compared by something that
// carries the classification". The three known instances were spelled three
// different ways - `hop == p` on a comparable struct, `ap.String() !=
// author.String()`, and `seen[a.ID.String()]` - and a textual sweep for any
// one of those spellings finds neither of the others. #3878 asked for the
// enumeration to be structural for exactly that reason, and the third instance
// (contract.Request.Validate) was found by this scanner rather than by reading.
//
// The domain is every package of every module in the checkout whose go.mod can
// reach axonflow/platform or axonflow/platform/decision, under BOTH build tag
// sets. A package outside that set cannot have a value of either type in scope,
// so the module filter is a sound over-approximation rather than a convenience.
//
// The module domain, the type-checker and the per-checkout list of
// configurations the go command cannot list are platform/testutil/gocensus,
// shared with the legacy-freeze writer census (#4084).

import (
	"bytes"
	"go/ast"
	"go/printer"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"axonflow/platform/testutil/gocensus"
)

// The two types whose comparison this census is about, by full name.
const (
	principalIDType = "axonflow/platform/shared/identity.PrincipalID"
	contractIDType  = "axonflow/platform/decision/contract.ID"
)

// The module paths that define them. Discovery must find both; a checkout in
// which it finds neither is a checkout this census cannot say anything about.
const (
	platformModule = "axonflow/platform"
	decisionModule = "axonflow/platform/decision"
)

// comparisonSite is one place two identifiers are decided to be the same or
// different.
//
// IT IS KEYED ON THE ENCLOSING DECLARATION AND THE NORMALISED EXPRESSION, NOT
// ON A LINE NUMBER. A census keyed on a source position goes red on a
// comment-only sweep and has to be re-baselined, which trains everyone to
// re-baseline it (#3840). The expression text is whitespace-normalised, so it
// survives gofmt and a rename of a surrounding block, and it changes when an
// operand changes - which is the edit a count-based ratchet cannot see.
type comparisonSite struct {
	// Module is the go.mod module path the package belongs to.
	Module string
	// Pkg is the import path.
	Pkg string
	// Decl names the enclosing function or declaration, with its receiver.
	Decl string
	// Form is how the comparison is spelled; see the form constants.
	Form string
	// Type is the full name of the identifier type involved.
	Type string
	// Expr is the normalised source text of the deciding expression.
	Expr string
}

// The spellings this scanner recognises. Each is a way to decide that two
// identifiers are the same one, and the first four carry the classification
// while the fifth deliberately does not.
const (
	// formCompare is `a == b` or `a != b` on a value whose type is, or
	// contains, one of the two identifier types.
	formCompare = "compare"
	// formCompareRendered is the same comparison on `a.String()`.
	formCompareRendered = "compare-rendered"
	// formMapKey is a map type whose key is, or contains, one of them.
	formMapKey = "map-key"
	// formKeyRendered is an index expression whose key is `a.String()`.
	// The map's own declaration says `map[string]...` and carries no signal,
	// so the index is the site - this is the shape the third instance had.
	formKeyRendered = "key-rendered"
	// formHelper is a call to an equality helper over one of the types.
	formHelper = "helper"
	// formConditionLiteral is a rendered identifier handed to a decision
	// CONDITION constructor, where the equality is carried out later by
	// another evaluator over strings.
	//
	// IT IS HERE BECAUSE A COMPARISON DOES NOT HAVE TO BE A GO OPERATOR. The
	// PDP compiles `Compare(principal.id, OpEq, p.String())`, and that decides
	// whether a policy applies to a subject exactly as `==` would - so a
	// census that only knew about Go expressions would report the policy
	// targeting surface as clean. It is the boundary of what this scanner can
	// see: an equality encoded for a THIRD evaluator (a SQL predicate, a Rego
	// rule authored by hand) is a different surface with a different
	// mechanism, and this census does not claim to cover those.
	formConditionLiteral = "condition-literal"
	// formIdentity is a call to one of the identity comparisons, which fold
	// the classification on purpose. It is enumerated so the census covers
	// BOTH directions: a site that must compare exactly and was "fixed" to
	// compare identities is the same defect pointing the other way, and it
	// would otherwise be invisible here.
	formIdentity = "identity-helper"
)

// identityHelpers are the methods and functions that compare identities rather
// than classified values.
var identityHelpers = map[string]bool{
	"SameSubject": true,
	"SubjectKey":  true,
	"IdentityKey": true,
	"SameEntity":  true,
}

// equalityHelpers are the stdlib functions that decide equality over values
// passed to them, where an operand of one of the two types is the same
// decision as an `==`.
var equalityHelpers = map[string]bool{
	"reflect.DeepEqual":   true,
	"slices.Contains":     true,
	"slices.ContainsFunc": true,
	"slices.Index":        true,
	"slices.Equal":        true,
	"maps.Equal":          true,
	"strings.EqualFold":   true,
}

// scanModule type-checks every non-test package of one module under one build
// tag set and returns the comparison sites it finds.
//
// A package that cannot be type-checked is returned as a FAILURE rather than
// skipped. "No findings" and "no data" are the same output otherwise, and a
// census that silently stops scanning a package is a census that reports a
// clean tree for the one package nobody looked at.
// TEST FILES ARE OUT OF SCOPE, and that is a deliberate boundary rather than a
// gap. A comparison inside a _test.go file cannot decide who approves a policy
// in a running deployment, and including the suites would bury the inventory
// in fixtures.
func scanModule(modDir, tags string) (sites []comparisonSite, failures []string, err error) {
	m, err := gocensus.Load(modDir, tags)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range m.Packages {
		if p.Error != nil {
			failures = append(failures, p.ImportPath+": go list: "+p.Error.Err)
			continue
		}
		modPath := ""
		if p.Module != nil {
			modPath = p.Module.Path
		}
		files, _, perr := m.Parse(p.ImportPath, nil)
		if perr != nil {
			failures = append(failures, p.ImportPath+": parse: "+perr.Error())
			continue
		}
		if len(files) == 0 {
			continue
		}
		found, terr := scanPackageFiles(m.Fset, m.Importer, p.ImportPath, modPath, files)
		if terr != nil {
			failures = append(failures, p.ImportPath+": type-check: "+terr.Error())
			continue
		}
		sites = append(sites, found...)
	}
	return sites, failures, nil
}

// scanPackageFiles type-checks one package's syntax and walks it.
//
// It is separated from scanModule so the planted-input control can hand it
// synthetic files parsed from memory, which is how this census is proved able
// to report a site without writing anything into the tree. A harness that
// plants by editing a file in a shared clone can leave the plant behind, and
// the next run then treats the plant as the baseline.
func scanPackageFiles(
	fset *token.FileSet, imp types.Importer, importPath, modPath string, files []*ast.File,
) ([]comparisonSite, error) {
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{},
		Uses:  map[*ast.Ident]types.Object{},
	}
	conf := types.Config{
		Importer: imp,
		// Errors are collected by the return value rather than by this hook;
		// the hook exists so type-checking does not stop at the first one and
		// leave Info half-populated.
		Error:                    func(error) {},
		DisableUnusedImportCheck: true,
	}
	if _, err := conf.Check(importPath, fset, files, info); err != nil {
		return nil, err
	}

	var out []comparisonSite
	for _, f := range files {
		w := &siteWalker{fset: fset, info: info, mod: modPath, pkg: importPath}
		w.walkFile(f)
		out = append(out, w.sites...)
	}
	return out, nil
}

// siteWalker carries the per-file state of the walk.
type siteWalker struct {
	fset  *token.FileSet
	info  *types.Info
	mod   string
	pkg   string
	decl  []string
	sites []comparisonSite
}

// involves reports the identifier type reachable from t by value, and whether
// there is one.
//
// A POINTER IS NOT FOLLOWED. Comparing two pointers is pointer identity and
// says nothing about the values behind them; following one would report every
// `d == nil` on a struct that happens to contain an identifier, which is how
// the first draft of this produced forty rows of noise. A slice is not
// followed either, because a slice is not comparable - the element reaches
// this function on its own wherever it is actually compared.
func (w *siteWalker) involves(t types.Type, depth int) (string, bool) {
	if t == nil || depth > 6 {
		return "", false
	}
	if n, ok := t.(*types.Named); ok {
		if o := n.Obj(); o.Pkg() != nil {
			switch full := o.Pkg().Path() + "." + o.Name(); full {
			case principalIDType, contractIDType:
				return full, true
			}
		}
		return w.involves(n.Underlying(), depth+1)
	}
	switch u := t.(type) {
	case *types.Array:
		return w.involves(u.Elem(), depth+1)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if full, ok := w.involves(u.Field(i).Type(), depth+1); ok {
				return full, true
			}
		}
	}
	return "", false
}

func (w *siteWalker) typeOf(e ast.Expr) (string, bool) { return w.involves(w.info.TypeOf(e), 0) }

// renderedBy reports the identifier type whose String() produced e.
func (w *siteWalker) renderedBy(e ast.Expr) (string, bool) {
	call, ok := e.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "String" {
		return "", false
	}
	return w.typeOf(sel.X)
}

func (w *siteWalker) record(form, typ string, e ast.Expr) {
	var b bytes.Buffer
	_ = printer.Fprint(&b, w.fset, e)
	decl := "<file scope>"
	if len(w.decl) > 0 {
		decl = w.decl[len(w.decl)-1]
	}
	w.sites = append(w.sites, comparisonSite{
		Module: w.mod, Pkg: w.pkg, Decl: decl, Form: form, Type: typ,
		Expr: strings.Join(strings.Fields(b.String()), " "),
	})
}

func (w *siteWalker) walkFile(f *ast.File) {
	for _, d := range f.Decls {
		switch decl := d.(type) {
		case *ast.FuncDecl:
			w.push(funcName(w.fset, decl))
			if decl.Body != nil {
				ast.Inspect(decl.Body, w.visit)
			}
			// The signature is walked too: a parameter or result of a map type
			// keyed on an identifier is the same decision as one declared in
			// the body, and it is where several of this tree's are written.
			ast.Inspect(decl.Type, w.visit)
			w.pop()
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				w.push(specName(spec))
				ast.Inspect(spec, w.visit)
				w.pop()
			}
		}
	}
}

func (w *siteWalker) push(name string) { w.decl = append(w.decl, name) }
func (w *siteWalker) pop()             { w.decl = w.decl[:len(w.decl)-1] }

func (w *siteWalker) visit(n ast.Node) bool {
	switch x := n.(type) {
	case *ast.FuncLit:
		// A closure's body belongs to the enclosing declaration, which is
		// already on the stack; nothing to push.
		return true
	case *ast.BinaryExpr:
		if x.Op != token.EQL && x.Op != token.NEQ {
			return true
		}
		if typ, ok := w.typeOf(x.X); ok {
			w.record(formCompare, typ, x)
		} else if typ, ok := w.typeOf(x.Y); ok {
			w.record(formCompare, typ, x)
		} else if typ, ok := w.renderedBy(x.X); ok {
			w.record(formCompareRendered, typ, x)
		} else if typ, ok := w.renderedBy(x.Y); ok {
			w.record(formCompareRendered, typ, x)
		}
	case *ast.MapType:
		if typ, ok := w.typeOf(x.Key); ok {
			w.record(formMapKey, typ, x)
		}
	case *ast.IndexExpr:
		// Only the RENDERED key is recorded here. An index into a map whose
		// key type is an identifier is a USE of a decision made where the map
		// type is written, and that declaration is already a formMapKey row;
		// recording both would bury fourteen decisions under sixty uses.
		if typ, ok := w.renderedBy(x.Index); ok {
			w.record(formKeyRendered, typ, x)
		}
	case *ast.CallExpr:
		w.visitCall(x)
	}
	return true
}

// conditionConstructors are the decision-policy condition builders whose
// literal operand becomes an equality performed by the compiled evaluator.
var conditionConstructors = map[string]bool{"Compare": true, "Intersects": true}

func (w *siteWalker) visitCall(x *ast.CallExpr) {
	if name := calleeName(x.Fun); conditionConstructors[name] {
		for _, a := range x.Args {
			if typ, ok := w.renderedBy(a); ok {
				w.record(formConditionLiteral, typ, x)
				return
			}
		}
	}
	sel, ok := x.Fun.(*ast.SelectorExpr)
	if ok && identityHelpers[sel.Sel.Name] {
		if typ, found := w.typeOf(sel.X); found {
			w.record(formIdentity, typ, x)
			return
		}
	}
	if ok {
		if pkgIdent, isIdent := sel.X.(*ast.Ident); isIdent {
			name := pkgIdent.Name + "." + sel.Sel.Name
			if equalityHelpers[name] {
				w.recordFirstIdentifierArg(formHelper+":"+name, x)
				return
			}
			if identityHelpers[sel.Sel.Name] {
				// A package-qualified identity comparison, e.g.
				// contract.SameEntity(a, b).
				w.recordFirstIdentifierArg(formIdentity, x)
				return
			}
		}
	}
	if id, isIdent := x.Fun.(*ast.Ident); isIdent && identityHelpers[id.Name] {
		w.recordFirstIdentifierArg(formIdentity, x)
	}
}

func (w *siteWalker) recordFirstIdentifierArg(form string, x *ast.CallExpr) {
	for _, a := range x.Args {
		if typ, ok := w.typeOf(a); ok {
			w.record(form, typ, x)
			return
		}
		if typ, ok := w.renderedBy(a); ok {
			w.record(form+"-rendered", typ, x)
			return
		}
	}
}

// calleeName returns the bare name of a called function, whether it is called
// plain or through a package qualifier.
func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// funcName renders a function declaration's name with its receiver.
func funcName(fset *token.FileSet, d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return d.Name.Name
	}
	var b bytes.Buffer
	_ = printer.Fprint(&b, fset, d.Recv.List[0].Type)
	return "(" + b.String() + ")." + d.Name.Name
}

// specName names a top-level declaration so a file-scope site has an anchor
// that is not a line number.
func specName(spec ast.Spec) string {
	switch s := spec.(type) {
	case *ast.TypeSpec:
		return "type " + s.Name.Name
	case *ast.ValueSpec:
		names := make([]string, len(s.Names))
		for i, n := range s.Names {
			names[i] = n.Name
		}
		return "var " + strings.Join(names, ", ")
	}
	return "<file scope>"
}

// reference is one place a named package-level function is mentioned.
type reference struct {
	Pkg    string
	Decl   string
	Target string
}

// scanReferences reports every mention of the named package-level functions
// across one module under one tag set.
//
// It reads types.Info.Uses rather than matching call syntax, so a function
// taken as a VALUE and called indirectly is still a reference. That matters
// for what this is used for: "nothing reaches this code" has to survive an
// indirection, or it is a claim about a spelling rather than about reachability.
func scanReferences(modDir, tags string, targets map[string]bool) (refs []reference, failures []string, err error) {
	m, err := gocensus.Load(modDir, tags)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range m.Packages {
		if p.Error != nil {
			failures = append(failures, p.ImportPath+": go list: "+p.Error.Err)
			continue
		}
		files, _, perr := m.Parse(p.ImportPath, nil)
		if perr != nil || len(files) == 0 {
			if perr != nil {
				failures = append(failures, p.ImportPath+": parse: "+perr.Error())
			}
			continue
		}
		info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}}
		conf := types.Config{Importer: m.Importer, Error: func(error) {}, DisableUnusedImportCheck: true}
		if _, terr := conf.Check(p.ImportPath, m.Fset, files, info); terr != nil {
			failures = append(failures, p.ImportPath+": type-check: "+terr.Error())
			continue
		}
		for _, f := range files {
			var decl []string
			var walk func(ast.Node) bool
			walk = func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.FuncDecl:
					decl = append(decl, funcName(m.Fset, x))
					if x.Body != nil {
						ast.Inspect(x.Body, walk)
					}
					decl = decl[:len(decl)-1]
					return false
				case *ast.Ident:
					o := info.Uses[x]
					if o == nil || o.Pkg() == nil {
						return true
					}
					full := o.Pkg().Path() + "." + o.Name()
					if !targets[full] {
						return true
					}
					// A function DECLARATION's own name is in Defs, not Uses,
					// so nothing here reports a target as referencing itself.
					where := "<file scope>"
					if len(decl) > 0 {
						where = decl[len(decl)-1]
					}
					refs = append(refs, reference{Pkg: p.ImportPath, Decl: where, Target: full})
				}
				return true
			}
			ast.Inspect(f, walk)
		}
	}
	return refs, failures, nil
}

// sortSites orders sites so a failure message is stable between runs.
func sortSites(sites []comparisonSite) {
	sort.Slice(sites, func(i, j int) bool {
		a, b := sites[i], sites[j]
		switch {
		case a.Pkg != b.Pkg:
			return a.Pkg < b.Pkg
		case a.Decl != b.Decl:
			return a.Decl < b.Decl
		case a.Form != b.Form:
			return a.Form < b.Form
		default:
			return a.Expr < b.Expr
		}
	})
}
