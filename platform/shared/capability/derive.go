// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// enterpriseSourceRe is the community sync's build-constraint expression, the
// one definition of "enterprise-only source" in this repository.
// .github/workflows/sync-community-repo.yml and
// .github/scripts/check-enterprise-leak.sh delete every Go file it matches
// before the mirror is published. The expression is kept byte-identical at
// every site by tests/regression-test-required/enterprise_tag_regex_single_definition_test.sh,
// because a classifier that drifts from the sync classifies a different mirror.
var enterpriseSourceRe = regexp.MustCompile(`(?m)^//go:build enterprise|^// \+build enterprise`)

// SourceEdition classifies a repository-relative Go path by the community
// sync's three DELETION mechanisms: ee/ is excluded wholesale,
// *_enterprise.go and *_enterprise_test.go are deleted by name, and any file
// whose build constraint selects the enterprise build is deleted by the scan.
// Everything else reaches the mirror and is community.
//
// A classifier that knows only some of the three reports a stripped file as a
// deleted one. platform/shared/policy's census carries the same function for
// the same reason; the shared thing between them is the expression above,
// which one test pins across every site.
func SourceEdition(root, rel string) (string, error) {
	if strings.HasPrefix(rel, "ee/") ||
		strings.HasSuffix(rel, "_enterprise.go") ||
		strings.HasSuffix(rel, "_enterprise_test.go") {
		return "enterprise", nil
	}
	src, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		return "", err
	}
	if enterpriseSourceRe.Match(src) {
		return "enterprise", nil
	}
	return "community", nil
}

// TreeIsCommunityMirror reports whether this checkout is the public mirror,
// which the sync produces without ee/. The same discriminator is used by the
// repository's workflow guards and by platform/shared/policy's census.
func TreeIsCommunityMirror(root string) bool {
	_, err := os.Stat(filepath.Join(root, "ee"))
	return err != nil
}

// RouteSite is one HTTP route-registration call site found in the source.
type RouteSite struct {
	// Pattern is the resolved path, empty when Resolved is false.
	Pattern string
	// Expr is the source text of the argument as written, which is what a
	// reviewer needs when the scanner could not resolve it.
	Expr string
	// Method is the registration method: HandleFunc, Handle, PathPrefix, Path.
	Method string
	// File is repo-relative; Line is 1-indexed.
	File string
	Line int
	// Edition is "enterprise" when the file is deleted from the community
	// mirror by one of the sync's three mechanisms, "community" otherwise.
	Edition string
	// Resolved says whether Pattern is trustworthy.
	Resolved bool
}

// Derivation is the whole result of one walk of the tree.
type Derivation struct {
	// Routes are every registration site, in file order.
	Routes []RouteSite
	// EnterpriseDirs are the package directories holding at least one
	// non-test file the community mirror deletes.
	EnterpriseDirs []string
	// FilesParsed and DirsWalked exist so a caller can prove the walk
	// happened. A derivation that parsed nothing produces an empty inventory,
	// and an empty inventory satisfies every coverage check ever written.
	FilesParsed int
	DirsWalked  int
}

// Patterns returns the distinct resolved route patterns, sorted.
func (d *Derivation) Patterns() []string {
	seen := map[string]bool{}
	for _, s := range d.Routes {
		if s.Resolved {
			seen[s.Pattern] = true
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Unresolved returns the sites whose path argument the scanner could not
// follow, in file order.
func (d *Derivation) Unresolved() []RouteSite {
	var out []RouteSite
	for _, s := range d.Routes {
		if !s.Resolved {
			out = append(out, s)
		}
	}
	return out
}

// unknownPrefix marks a subrouter whose own prefix the scanner could not
// resolve. It cannot appear in a path, so it can never be mistaken for one.
const (
	// ambiguousSentinel marks an identifier two same-named packages declare
	// with different values. It cannot be a path, so it can never resolve.
	ambiguousSentinel = "\x00ambiguous"
	unknownPrefix     = "\x00unknown-subrouter-prefix"
	unknownPrefixNote = "<subrouter with an unresolved prefix>"
)

// routeMethods are the gorilla/mux and net/http registration methods whose
// first argument is a path.
//
// `Handle` is in the list and is the reason the scanner reports an
// unresolvable argument instead of skipping it: `Handle` is also an ordinary
// method name on ordinary types, so a scanner that silently ignored the ones
// it could not resolve would also silently ignore a real route registered
// through a value it did not understand. Reporting turns both into a reviewed
// line in the registry's route_exemptions rather than a hole.
// unambiguousRouteMethods are the route methods that are not also common
// struct-field names. `Path` is the one left out: url.URL.Path is read by every
// request handler.
var unambiguousRouteMethods = map[string]bool{
	"HandleFunc": true,
	"Handle":     true,
	"PathPrefix": true,
}

var routeMethods = map[string]bool{
	"HandleFunc": true,
	"Handle":     true,
	"PathPrefix": true,
	"Path":       true,
}

// parsedFile is one parsed source file with the classification of its edition.
type parsedFile struct {
	rel     string
	file    *ast.File
	edition string
}

// Derive walks roots under repoRoot, parses every non-test Go file, and
// returns every route-registration site together with the build-constraint
// classification of the file it was found in.
//
// It PARSES rather than greps, and that is not fastidiousness. On main,
// nineteen registration sites name a constant rather than a string literal,
// and two of them are POST /api/v1/decide and POST /api/v1/access/evaluation —
// the platform's two most-called governance surfaces. A regex over `"/api/v1`
// finds neither, and a census built on it would report full coverage of a
// route set missing its most important members.
func Derive(repoRoot string, roots []string) (*Derivation, error) {
	d := &Derivation{}
	fset := token.NewFileSet()

	var files []parsedFile
	// specs are every top-level const/var declaration seen during the walk;
	// consts is the fixpoint resolution of them, keyed by "<dir>\x00<Ident>"
	// and by "<pkgName>.<Ident>". Both keys are needed: a registration in the
	// same package names a bare identifier, and one in another package names
	// pkg.Ident.
	var specs []constSpec
	var consts map[string]string

	for _, root := range roots {
		abs := filepath.Join(repoRoot, root)
		if _, err := os.Stat(abs); err != nil {
			// A scan root that is absent is not automatically an error: the
			// community mirror has no ee/. It IS an error in a tree that has
			// ee/, and the CALLER decides, because only the caller knows which
			// tree it is looking at.
			continue
		}
		err := filepath.WalkDir(abs, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				switch entry.Name() {
				case "testdata", "node_modules", ".git", "vendor":
					return filepath.SkipDir
				}
				d.DirsWalked++
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				return relErr
			}
			rel = filepath.ToSlash(rel)
			f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if perr != nil {
				return fmt.Errorf("parsing %s: %w", rel, perr)
			}
			ed, eerr := SourceEdition(repoRoot, rel)
			if eerr != nil {
				return eerr
			}
			d.FilesParsed++
			files = append(files, parsedFile{rel: rel, file: f, edition: ed})
			collectConstSpecs(f, filepath.ToSlash(filepath.Dir(rel)), &specs)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// The fixpoint runs AFTER the whole walk, so a constant defined in terms of
	// one declared in another file resolves whichever order the walk reached
	// them in.
	consts = resolveConsts(specs)

	byDir := map[string][]parsedFile{}
	for _, pf := range files {
		d := filepath.ToSlash(filepath.Dir(pf.rel))
		byDir[d] = append(byDir[d], pf)
	}
	scopes := map[string]packageScope{}
	for d, group := range byDir {
		scopes[d] = buildPackageScope(group, d, consts)
	}

	for _, pf := range files {
		dir := filepath.ToSlash(filepath.Dir(pf.rel))
		sites := scanFile(fset, pf.file, pf.rel, dir, pf.edition, consts, scopes[dir])
		d.Routes = append(d.Routes, sites...)
		if pf.edition == "enterprise" {
			d.EnterpriseDirs = append(d.EnterpriseDirs, dir)
		}
	}
	d.EnterpriseDirs = dedupeSorted(d.EnterpriseDirs)
	sort.SliceStable(d.Routes, func(i, j int) bool {
		if d.Routes[i].File != d.Routes[j].File {
			return d.Routes[i].File < d.Routes[j].File
		}
		return d.Routes[i].Line < d.Routes[j].Line
	})
	return d, nil
}

// constSpec is one top-level `const`/`var` declaration whose value might be a
// compile-time string.
type constSpec struct {
	dir  string
	pkg  string
	name string
	expr ast.Expr
}

// collectConstSpecs records every top-level const/var declaration for later
// resolution. It does NOT resolve them here, because a constant may be defined
// in terms of another constant — `const mid = base + "/mid"` — and resolving as
// the walk goes would depend on file order and would silently fail to follow
// the chain. Resolution is a fixpoint over the whole collected set.
func collectConstSpecs(f *ast.File, dir string, into *[]constSpec) {
	pkg := f.Name.Name
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
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
				*into = append(*into, constSpec{dir: dir, pkg: pkg, name: name.Name, expr: vs.Values[i]})
			}
		}
	}
}

// resolveConsts folds the collected declarations to a fixpoint, so a constant
// defined in terms of another constant resolves however the two are ordered
// across files. Each round can only ADD entries, so the loop terminates; the
// bound is belt and braces against a future edit that made a round remove one.
func resolveConsts(specs []constSpec) map[string]string {
	out := map[string]string{}
	// Progress is tracked PER SPEC, not by the size of the output map.
	//
	// The first version skipped a spec once its directory key was populated,
	// which meant the SECOND declaration of a name never reached record() and
	// the ambiguity sentinel could not fire from it — so two build-tag variants
	// in one directory declaring the same constant with different values
	// resolved to whichever the walk reached first, silently. The guard existed
	// and was unreachable, which is worse than not having written it: the code
	// reads as if the case is handled.
	//
	// Every spec is now resolved exactly once and every resolution goes through
	// record(), which is the only place that can see two values for one key.
	// Resolve to a fixpoint. Order within a round does not matter, because the
	// transitive propagation below is what actually holds the property: an
	// earlier draft snapshotted the map per round (Jacobi) so a value could not
	// be consumed in the round its conflict landed, and once the propagation
	// existed that snapshot became code no mutant could kill — reverting it to
	// resolve in place changed no outcome. Machinery a test cannot kill reads
	// as if it is doing something, so it is gone and the propagation carries
	// the whole weight, where it can be seen to.
	resolved := make([]bool, len(specs))
	for round := 0; round <= len(specs)+1; round++ {
		progress := false
		for i, sp := range specs {
			if resolved[i] {
				continue
			}
			v, ok := staticString(sp.expr, out, sp.dir)
			if !ok {
				continue
			}
			resolved[i] = true
			progress = true
			record(out, sp, v)
		}
		if !progress {
			break
		}
	}

	// A DECLARATION THAT NEVER RESOLVED POISONS ITS KEY.
	//
	// `const P = "/x"` beside `var P = os.Getenv("P")` in one directory: the var
	// never resolves, so it never reaches record(), and P kept the const's value
	// with total confidence. An unreadable declaration of a name is exactly as
	// disqualifying as a conflicting readable one — in both cases the scanner
	// cannot say what the identifier means.
	for i, sp := range specs {
		if resolved[i] {
			continue
		}
		out[sp.dir+"\x00"+sp.name] = ambiguousSentinel
		out[sp.pkg+"."+sp.name] = ambiguousSentinel
	}

	// AND THE POISON PROPAGATES TRANSITIVELY.
	//
	// Jacobi rounds stop a value being consumed in the SAME round its conflict
	// lands, and that is not enough: `Q = P + "/x"` commits in whatever round P
	// becomes readable, and if P's second declaration only resolves LATER —
	// `P = Base + "/comm"` needs Base first — Q is already committed and never
	// revisited. Worse, the answer was ORDER-DEPENDENT: moving the literal from
	// one file to the other changed which value Q held.
	//
	// So after the fixpoint, anything derived from an ambiguous key becomes
	// ambiguous itself, repeatedly, until nothing changes.
	for round := 0; round <= len(specs)+1; round++ {
		changed := false
		for _, sp := range specs {
			key := sp.dir + "\x00" + sp.name
			if out[key] == ambiguousSentinel {
				continue
			}
			for _, ref := range referencedKeys(sp.expr, sp.dir) {
				if out[ref] != ambiguousSentinel {
					continue
				}
				out[key] = ambiguousSentinel
				out[sp.pkg+"."+sp.name] = ambiguousSentinel
				changed = true
				break
			}
		}
		if !changed {
			break
		}
	}
	return out
}

// referencedKeys returns the constant-map keys an expression reads, so the
// ambiguity of one declaration can be propagated to everything built on it.
func referencedKeys(e ast.Expr, dir string) []string {
	var out []string
	ast.Inspect(e, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if x, ok := v.X.(*ast.Ident); ok {
				out = append(out, x.Name+"."+v.Sel.Name)
			}
			return false
		case *ast.Ident:
			out = append(out, dir+"\x00"+v.Name)
		}
		return true
	})
	return out
}

// record stores a resolved declaration under both keys.
//
// BOTH keys get the ambiguity sentinel, and the directory key is the one that
// matters most. Two mutually exclusive build-tag variants in ONE directory can
// declare the same constant with different values — which is precisely the
// shape 48 enterprise-tagged directories are full of — and go/parser reads both
// files, so without the sentinel one value silently wins by walk order.
func record(into map[string]string, sp constSpec, v string) {
	dirKey := sp.dir + "\x00" + sp.name
	if prev, dup := into[dirKey]; dup && prev != v {
		into[dirKey] = ambiguousSentinel
	} else if _, taken := into[dirKey]; !taken {
		into[dirKey] = v
	}
	{
		pkg, name := sp.pkg, sp.name
		// The package-qualified key is only unambiguous when one package of
		// that name declares the identifier. A second declaration under the
		// same key is dropped rather than overwritten, so a collision degrades
		// to "unresolved" and is reported, instead of silently resolving to
		// whichever file the walk happened to reach last.
		pkgKey := pkg + "." + name
		if prev, dup := into[pkgKey]; dup && prev != v {
			into[pkgKey] = ambiguousSentinel
			return
		}
		if _, taken := into[pkgKey]; !taken {
			into[pkgKey] = v
		}
	}
}

// staticString resolves an expression to a compile-time string when it can.
// consts may be nil, in which case only literals and their concatenations
// resolve — which is what const collection needs, since it runs before the
// whole map exists.
func staticString(e ast.Expr, consts map[string]string, dir string) (string, bool) {
	return staticStringScoped(e, consts, dir, nil)
}

// staticStringScoped is staticString with a set of identifiers that the
// enclosing function BINDS, and which therefore must not resolve to a
// package-level constant of the same name.
//
// Without it a range variable named like a const takes the const's value, and
// the scanner reports a route the server does not serve. Being coarse — any
// binding anywhere in the function shadows for the whole of it — errs towards
// an admitted unknown, which is the safe direction.
func staticStringScoped(e ast.Expr, consts map[string]string, dir string, shadowed map[string]bool) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, lok := staticStringScoped(v.X, consts, dir, shadowed)
		r, rok := staticStringScoped(v.Y, consts, dir, shadowed)
		if !lok || !rok {
			return "", false
		}
		return l + r, true
	case *ast.Ident:
		if consts == nil || shadowed[v.Name] {
			return "", false
		}
		s, ok := consts[dir+"\x00"+v.Name]
		if !ok || s == ambiguousSentinel {
			return "", false
		}
		return s, true
	case *ast.SelectorExpr:
		if consts == nil {
			return "", false
		}
		x, ok := v.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		s, ok := consts[x.Name+"."+v.Sel.Name]
		if !ok || s == ambiguousSentinel {
			return "", false
		}
		return s, true
	case *ast.ParenExpr:
		return staticStringScoped(v.X, consts, dir, shadowed)
	default:
		return "", false
	}
}

// scanFile finds the registration sites in one file.
//
// Three properties, each of which the first version of this function got wrong
// and each of which produces an INVENTED path rather than a missing one:
//
//   - subrouter variables are learned from `:=` AND from `var x = ...`, and a
//     chained `r.PathPrefix(P).Subrouter().HandleFunc(...)` is resolved from
//     the receiver directly. A learner keyed on `:=` alone reports the child of
//     a `var` subrouter as a top-level route.
//   - the subrouter map is scoped PER FUNCTION BODY, not per file. A bare
//     identifier has no lexical scope in an AST walk, so a file-scoped map
//     lets one function's subrouter variable rename another function's
//     PARAMETER of the same name. That is not hypothetical: on main,
//     ee/platform/customer-portal/main.go names a subrouter `apiRouter` and
//     three functions take a parameter of that name. It is correct there only
//     because those parameters happen to be that router.
//   - an identifier BOUND INSIDE the function does not resolve to a
//     package-level constant of the same name. A range variable shadowing a
//     const otherwise yields the const's value.
//
// The scoping is function-level rather than block-level, which is coarser than
// Go's own rule. That is deliberate: being coarse here turns a resolvable path
// into a REPORTED unknown, which costs a reviewed exemption, while being
// precise and wrong invents a path nothing serves.
func scanFile(fset *token.FileSet, f *ast.File, rel, dir, edition string,
	consts map[string]string, pkg packageScope) []RouteSite {
	var out []RouteSite

	record := func(method string, arg ast.Expr, pos token.Pos, prefix string, shadowed map[string]bool) {
		site := RouteSite{
			Method:  method,
			File:    rel,
			Line:    fset.Position(pos).Line,
			Edition: edition,
			Expr:    exprText(arg),
		}
		// An unknown subrouter prefix makes every registration on it unknown
		// too, however well the suffix resolves. Concatenating a known suffix
		// onto an unknown prefix would produce a confident wrong path, which
		// is worse than an admitted unknown: a registry entry could be written
		// to match it and the coverage check would then pass on a URL the
		// server never serves.
		if prefix == unknownPrefix {
			site.Expr = unknownPrefixNote + site.Expr
			out = append(out, site)
			return
		}
		if s, ok := staticStringScoped(arg, consts, dir, shadowed); ok {
			site.Pattern = prefix + s
			site.Resolved = true
		}
		// A `Handle` call whose argument resolves to something that is not a
		// path is not a route registration at all — it is any other method
		// called Handle. An UNRESOLVED argument is still reported, because the
		// alternative is a scanner that decides on its own which arguments it
		// failed to read were routes.
		if site.Resolved && !strings.HasPrefix(site.Pattern, "/") {
			return
		}
		out = append(out, site)
	}

	pkgMethodValues := pkg.methodValues
	pkgSubs := pkg.subrouters

	// scanBody walks one function body. It is recursive because a closure is
	// not a fresh scope: a FuncLit SEES the enclosing function's variables, so
	// it inherits the subrouter map — minus anything it binds itself, which
	// shadows. Scanning a FuncLit with an empty map loses a real prefix;
	// scanning it with the outer map and no shadowing invents one, which is
	// what the first version did.
	var scanBody func(body ast.Node, params map[string]bool,
		inheritedSub map[string]string, inheritedShadow map[string]bool,
		inheritedMV map[string]RouteSite, inheritedRoots map[string]bool)

	scanBody = func(body ast.Node, params map[string]bool,
		inheritedSub map[string]string, inheritedShadow map[string]bool,
		inheritedMV map[string]RouteSite, inheritedRoots map[string]bool) {

		// TWO SETS, and conflating them cost a closure its inherited prefix.
		//
		//   localBound  — names THIS body binds. These shadow an inherited
		//                 subrouter, because the name now means something else
		//                 here.
		//   shadowed    — localBound plus every name an ENCLOSING body bound,
		//                 used only to stop an identifier resolving to a
		//                 package-level constant.
		//
		// The inherited bindings must not shadow the inherited subrouter map:
		// they are what BUILT it. The first version applied `shadowed` to the
		// map and a closure that bound nothing lost the outer subrouter it can
		// plainly see.
		localBound := map[string]bool{}
		for k := range params {
			localBound[k] = true
		}
		// bodyBound is localBound MINUS the parameters: the names this body
		// declares for itself. The two must not be conflated — parameters are
		// what rule (a) prices, so removing them from `roots` alongside the
		// body's own bindings would un-price every `func R(r *mux.Router)` in
		// the tree, which is exactly what the first draft of this inversion
		// did (17 attributed capabilities instead of 84).
		bodyBound := map[string]bool{}
		shadowed := map[string]bool{}
		for k := range inheritedShadow {
			shadowed[k] = true
		}
		for k := range params {
			shadowed[k] = true
		}
		subPrefix := map[string]string{}
		for k, v := range inheritedSub {
			subPrefix[k] = v
		}
		// lostPrefix names a subrouter this scope SHADOWS with something the
		// scanner cannot read. Falling back to no prefix there would assume a
		// plain router, and we know better: the name meant a prefixed
		// subrouter one scope out, and now means something we cannot follow.
		// Assuming is how an invented path gets made; the honest answer is to
		// report.
		lostPrefix := map[string]bool{}
		// roots are the names this body may price at the EMPTY prefix. Under
		// the round-8 inversion nothing else reaches it.
		//
		//   (a) this function's own parameters and receiver — the stated
		//       assumption that a router handed to a function is a plain one,
		//       which is what makes `func R(r *mux.Router)` scannable at all;
		//   (b) a local bound to `mux.NewRouter()`;
		//   (c) a proven package-level root;
		//   plus whatever an enclosing body proved, because a closure sees it.
		//
		// A parameter REASSIGNED in this body leaves the set: `func R(r *mux.
		// Router) { r = pick() ... }` is not the router that was handed in.
		roots := map[string]bool{}
		for k := range inheritedRoots {
			roots[k] = true
		}
		for k := range pkg.roots {
			roots[k] = true
		}
		for k := range params {
			roots[k] = true
		}
		// methodValues are names bound to a route method WITHOUT calling it.
		// A site is emitted only when one is later invoked.
		// Method values are inherited by closures for the same reason
		// subrouters are: a func literal sees them.
		methodValues := map[string]RouteSite{}
		for k, v := range pkgMethodValues {
			methodValues[k] = v
		}
		for k, v := range inheritedMV {
			methodValues[k] = v
		}

		// Pass 1: every name this body binds. It does NOT descend into a
		// nested FuncLit, whose bindings are its own scope.
		collect := func(n ast.Node) {
			ast.Inspect(n, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.FuncLit:
					return false
				case *ast.AssignStmt:
					if v.Tok != token.DEFINE {
						return true
					}
					for _, lhs := range v.Lhs {
						if id, ok := lhs.(*ast.Ident); ok {
							shadowed[id.Name] = true
							localBound[id.Name] = true
							bodyBound[id.Name] = true
						}
					}
				case *ast.RangeStmt:
					for _, e := range []ast.Expr{v.Key, v.Value} {
						if id, ok := e.(*ast.Ident); ok {
							shadowed[id.Name] = true
							localBound[id.Name] = true
							bodyBound[id.Name] = true
						}
					}
				case *ast.ValueSpec:
					for _, id := range v.Names {
						shadowed[id.Name] = true
						localBound[id.Name] = true
						bodyBound[id.Name] = true
					}
				}
				return true
			})
		}
		collect(body)

		// A name this body BINDS or ASSIGNS is no longer the thing the outer
		// scope proved. A parameter reassigned in the body, a package-level
		// root shadowed by a local, an inherited root rebound in a closure —
		// each leaves the roots set and falls back to the inverted default.
		for name := range bodyBound {
			delete(roots, name)
		}
		// AND IT DESCENDS INTO CLOSURES, which the first version did not.
		//
		// `collect` skips a FuncLit because a closure's own `:=` BINDINGS are
		// its own scope. An `=` ASSIGNMENT is the opposite: it writes to the
		// name the closure closed over, so `f := func() { r = other() }`
		// leaves the outer `r` as something this scanner cannot follow, and
		// the registration after it was still priced as the parameter.
		//
		// Descending unconditionally over-poisons in one case — a closure that
		// binds its own `r` first and then assigns to THAT — and that is the
		// direction to err in: the cost is one reported unknown, against a
		// path invented from a router that was swapped out from under it.
		ast.Inspect(body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || as.Tok == token.DEFINE {
				return true
			}
			for _, lhs := range as.Lhs {
				if id, plain := lhs.(*ast.Ident); plain {
					delete(roots, id.Name)
				}
			}
			return true
		})

		// A name this body binds shadows an inherited subrouter of the same
		// name. The learner below re-adds it when the binding is itself a
		// subrouter; otherwise the prefix is lost and must be reported.
		for name := range localBound {
			if _, had := subPrefix[name]; had {
				lostPrefix[name] = true
				delete(subPrefix, name)
			}
		}
		// Package-level subrouters are in scope everywhere this body is, minus
		// what it binds.
		for name, prefix := range pkgSubs {
			if localBound[name] {
				lostPrefix[name] = true
				continue
			}
			if _, inherited := subPrefix[name]; !inherited {
				subPrefix[name] = prefix
			}
		}

		// Pass 2: learn subrouter variables, record registrations, and recurse
		// into nested closures with this scope.
		ast.Inspect(body, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.FuncLit:
				scanBody(v.Body, boundNames(nil, v.Type), subPrefix, shadowed, methodValues, roots)
				return false
			case *ast.AssignStmt:
				for i, rhs := range v.Rhs {
					if i >= len(v.Lhs) {
						break
					}
					// A METHOD VALUE of a route method — `reg := r.HandleFunc`
					// — takes the registration out of reach entirely: the call
					// that follows is `reg(path, h)`, which is not a selector on
					// a router and matches nothing this scanner looks for. The
					// route is neither resolved NOR reported: the silent drop.
					//
					// THE REPORT FIRES ON THE CALL, NOT ON THE BINDING, and
					// that distinction is the whole of it. Reporting on the
					// binding meant `x.Path` on a right-hand side was flagged,
					// and without types that is indistinguishable from
					// `url.URL.Path` — four sites in this tree, all four a
					// request handler reading a struct field. A binding that is
					// never INVOKED registers nothing, so `s := req.URL.Path`
					// produces no site and needs no exemption, while
					// `p := r.Path; p("/x")` is reported. That keeps `Path` in
					// the set without crying wolf once.
					if mv, isSel := rhs.(*ast.SelectorExpr); isSel && routeMethods[mv.Sel.Name] {
						if name, plain := v.Lhs[i].(*ast.Ident); plain {
							methodValues[name.Name] = RouteSite{
								Method:  mv.Sel.Name,
								File:    rel,
								Edition: edition,
								Expr: "a method VALUE of a route method (" + exprText(rhs) +
									"), invoked as a function; the route it registers is one " +
									"this scanner cannot see",
							}
						}
					}
					name, ok := v.Lhs[i].(*ast.Ident)
					if !ok {
						continue
					}
					// An ALIAS of a subrouter is POISONED, not priced. Rule 1
					// of round 6: no new resolution path. `b := a` where a is a
					// known subrouter left b unlearned and its registrations
					// priced from the root, which is the one reading never to
					// take; carrying the prefix across would be a new
					// resolution path, so b is reported instead.
					if src, isIdent := rhs.(*ast.Ident); isIdent {
						if _, isSub := subPrefix[src.Name]; isSub {
							lostPrefix[name.Name] = true
							delete(subPrefix, name.Name)
						} else if lostPrefix[src.Name] {
							lostPrefix[name.Name] = true
						}
					}
					// An ALIAS of a method value is a method value. One
					// indirection was enough to go silent: `x := reg` then
					// `x(path, h)` matched nothing.
					if alias, isIdent := rhs.(*ast.Ident); isIdent {
						if site, isMV := methodValues[alias.Name]; isMV {
							methodValues[name.Name] = site
						}
					}
					if prefix, isSub := subrouterPrefix(rhs, consts, dir, shadowed, subPrefix, pkg.unfollowable, roots); isSub {
						subPrefix[name.Name] = prefix
						delete(lostPrefix, name.Name)
					}
					// A local root: `r := mux.NewRouter()`. Rule (b)'s other
					// half — a chain has to start somewhere, and inside a body
					// this is the only expression that proves a plain router.
					//
					// DEFINE ONLY. A plain `=` to a package-level name is not
					// rule (b): it is "assigned in a body", which the rule puts
					// squarely in the UNKNOWN column. Learning a root from it
					// priced `globalRouter` inside the one function that
					// assigns it, so `/health` resolved there and was reported
					// everywhere else — the same name answering differently in
					// two places, which is the shape the inversion exists to
					// remove. A second classifier arm happened to poison it
					// back, and a mechanism covering for another is not a
					// rule — that arm is gone and this line is the rule.
					if v.Tok == token.DEFINE && isNewRouterCall(rhs) {
						roots[name.Name] = true
						delete(lostPrefix, name.Name)
					}
				}
				return true
			case *ast.ValueSpec:
				for i, val := range v.Values {
					if i >= len(v.Names) {
						break
					}
					// The var form of the alias above.
					if src, isIdent := val.(*ast.Ident); isIdent {
						if _, isSub := subPrefix[src.Name]; isSub {
							lostPrefix[v.Names[i].Name] = true
							delete(subPrefix, v.Names[i].Name)
						} else if lostPrefix[src.Name] {
							lostPrefix[v.Names[i].Name] = true
						}
						if site, isMV := methodValues[src.Name]; isMV {
							methodValues[v.Names[i].Name] = site
						}
					}
					// `var reg = r.HandleFunc` binds a method value exactly as
					// `:=` does. The first version watched only AssignStmt, so
					// the var form was silent.
					if mv, isSel := val.(*ast.SelectorExpr); isSel && routeMethods[mv.Sel.Name] {
						methodValues[v.Names[i].Name] = RouteSite{
							Method:  mv.Sel.Name,
							File:    rel,
							Edition: edition,
							Expr: "a method VALUE of a route method (" + exprText(val) +
								"), invoked as a function; the route it registers is one " +
								"this scanner cannot see",
						}
					}
					if prefix, isSub := subrouterPrefix(val, consts, dir, shadowed, subPrefix, pkg.unfollowable, roots); isSub {
						subPrefix[v.Names[i].Name] = prefix
						delete(lostPrefix, v.Names[i].Name)
					}
					if isNewRouterCall(val) {
						roots[v.Names[i].Name] = true
						delete(lostPrefix, v.Names[i].Name)
					}
				}
				return true
			case *ast.CallExpr:
				// A call THROUGH a bound method value.
				// Only for an AMBIGUOUS method name. An unambiguous one was
				// already reported by the single sweep below, at the selector
				// itself; reporting it again here would double-count exactly
				// the shapes that have both a binding and a call.
				if callee, isIdent := v.Fun.(*ast.Ident); isIdent {
					if site, isMV := methodValues[callee.Name]; isMV && !unambiguousRouteMethods[site.Method] {
						site.Line = fset.Position(v.Lparen).Line
						out = append(out, site)
						return true
					}
				}
				sel, ok := v.Fun.(*ast.SelectorExpr)
				if !ok || !routeMethods[sel.Sel.Name] || len(v.Args) == 0 {
					return true
				}
				// THE INVERTED DEFAULT, at the site it matters most. Every
				// receiver is unknown until one of the proven shapes
				// recognises it, and there is nothing to consult in order to
				// REACH the sentinel: a name not on the list already holds it.
				prefix := unknownPrefix
				switch recv := sel.X.(type) {
				case *ast.Ident:
					// THREE ARMS, IN THIS ORDER, and the middle one is not
					// decoration.
					//
					//	1. what this body PROVED. A local `:=` can bind a name
					//	   the package also declares, and the local wins.
					//	2. what this body LOST. A name that shadows a known
					//	   subrouter with something unreadable is the one case
					//	   where the no-prefix assumption is known to be wrong:
					//	   the name meant a prefixed subrouter one scope out.
					//	   It must be REPORTED, so it has to be consulted
					//	   before rule (a) can price a shadowing parameter at
					//	   the root.
					//	3. a proven root.
					//
					// This arm shared a `case` with a `pending` check that the
					// inversion made redundant, and deleting the pair took it
					// with it — a shadowing parameter's route came out at "/"
					// and a test caught it. Removing redundant machinery is
					// only safe one mechanism at a time.
					switch {
					case isKnownSubrouter(subPrefix, recv.Name):
						prefix = subPrefix[recv.Name] // (b), (c)
					case lostPrefix[recv.Name]:
						prefix = unknownPrefix
					case roots[recv.Name]:
						prefix = "" // (a), or a local/package root
					}
				default:
					// (d): the immediate chained form, and nothing else. A
					// call result, an index, a field, a parenthesised name —
					// all keep the sentinel.
					if p, isSub := subrouterPrefix(sel.X, consts, dir, shadowed, subPrefix, pkg.unfollowable, roots); isSub {
						prefix = p
					}
				}
				record(sel.Sel.Name, v.Args[0], v.Lparen, prefix, shadowed)
				return true
			}
			return true
		})
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.FuncDecl:
			if v.Body == nil {
				return false
			}
			scanBody(v.Body, boundNames(v.Recv, v.Type), nil, nil, nil, nil)
			return false
		case *ast.FuncLit:
			// A top-level FuncLit, in a package-level initialiser. One inside a
			// function is reached by that function's own walk, with its scope.
			scanBody(v.Body, boundNames(nil, v.Type), nil, nil, nil, nil)
			return false
		}
		return true
	})

	// METHOD VALUES: ONE RULE, ONE SWEEP.
	//
	// A SelectorExpr whose selector is an unambiguous route method and which is
	// NOT the Fun of a CallExpr is a method VALUE — the method is being handed
	// somewhere rather than called — and every route it goes on to register is
	// beyond this scanner. It is reported wherever it appears: an assignment,
	// a var, a composite literal, a map literal, a struct field, an argument,
	// a return, a `defer`, a `go`.
	//
	// The rule replaces four separate detectors — binding, alias, argument,
	// call-through — that between them had to enumerate the syntactic
	// positions a method value can occupy. They missed the ones nobody
	// pictured: a value placed in a struct literal or a map literal and called
	// later produced NO SITE AT ALL, which is the silent-drop direction. The
	// position a value sits in tells you nothing about where it ends up, so
	// the position is the wrong thing to enumerate.
	//
	// `Path` keeps the invoked-only rule and is deliberately NOT in this
	// sweep. Without types, `req.URL.Path` is the same syntax as a route
	// method value, and this tree holds four of them; a binding that is never
	// INVOKED registers nothing, so the call through it is the only evidence
	// that settles which one it was.
	//
	// `Handle` IS in the sweep, and it is not free of the same ambiguity:
	// `slog.Handler`, `http.Handler` and anything else with a `Handle` method
	// would be reported if its method value were handed somewhere. That is
	// accepted rather than overlooked, on two grounds. It is measured: this
	// tree contains ZERO reported method values of any name, so the false
	// positive rate here is zero today, and a fixture below pins the
	// behaviour so a future one is a visible change rather than a surprise.
	// And the two errors are not symmetric — a false positive is one extra
	// line in an exemption-shaped report, while dropping `Handle` from the
	// sweep would silently lose every route registered through
	// `r.Handle` handed to a helper, which is the class this whole sweep
	// exists for. If the rate ever stops being zero, the fix is the same
	// call-through discriminator `Path` uses, not a narrower set.
	isFun := map[ast.Expr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			isFun[call.Fun] = true
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || !unambiguousRouteMethods[sel.Sel.Name] || isFun[sel] {
			return true
		}
		out = append(out, RouteSite{
			Method:  sel.Sel.Name,
			File:    rel,
			Line:    fset.Position(sel.Sel.NamePos).Line,
			Edition: edition,
			Expr: "a method VALUE of a route method (" + exprText(sel) +
				") is handed somewhere rather than called; the routes it registers " +
				"are beyond this scanner",
		})
		return true
	})

	// EVERY Subrouter() MUST BE BOUND TO A PLAIN IDENTIFIER, OR REPORTED.
	//
	// The learners recognise three homes for a subrouter: a `:=`, a `var`, and
	// an immediate chain. Anything else — a struct field, a map entry, a slice
	// element, a return value — is a subrouter the scanner cannot follow, and
	// its children would be recorded BARE: an invented top-level route, the
	// same failure H1 produced, in a shape nobody has planted yet.
	//
	// There are ZERO such sites in the tree today (measured: all ten
	// `.Subrouter()` calls bind to a local or package-level identifier), so
	// this reports nothing now. That is exactly when to add it — an unreadable
	// receiver has to become a REPORTED unknown at the moment the shape first
	// appears, not after a census has quietly claimed full coverage of a URL
	// space it could not read. Telling a prefixed subrouter from a plain router
	// through a struct field needs go/types; refusing to guess does not.
	claimed := map[ast.Node]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.AssignStmt:
			// Claim a right-hand side only when the LEARNER would actually
			// learn from it, which is when the left-hand side is a plain
			// identifier. `s.sub = r.PathPrefix(P).Subrouter()` is an
			// AssignStmt whose target the learner cannot key on, so claiming it
			// here would silence the report for exactly the shape the report
			// exists for. The claim condition and the learner's condition have
			// to be the same condition, and the first version of this had them
			// differ - which is how a guard ends up unable to fire.
			for i, rhs := range v.Rhs {
				if i >= len(v.Lhs) {
					break
				}
				if _, plain := v.Lhs[i].(*ast.Ident); plain {
					claimed[rhs] = true
				}
			}
		case *ast.ValueSpec:
			// A ValueSpec's names are always identifiers, so the learner
			// always learns and every value is claimed.
			for i, val := range v.Values {
				if i < len(v.Names) {
					claimed[val] = true
				}
			}
		case *ast.CallExpr:
			if sel, ok := v.Fun.(*ast.SelectorExpr); ok && routeMethods[sel.Sel.Name] {
				claimed[sel.X] = true
			}
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Subrouter" || claimed[call] {
			return true
		}
		out = append(out, RouteSite{
			Method:  "Subrouter",
			File:    rel,
			Line:    fset.Position(call.Lparen).Line,
			Edition: edition,
			Expr: "a subrouter bound to something the scanner cannot follow (" +
				exprText(sel.X) + ".Subrouter()); every registration on it would " +
				"be recorded without its prefix",
		})
		return true
	})

	// AND EVERYTHING OUTSIDE A FUNCTION BODY.
	//
	// Scoping the walk to function bodies is what fixed the parameter-shadow
	// defect, and it introduced a worse one in the same move: a registration in
	// a package-level initialiser — `var _ = globalRouter.HandleFunc(p, h)` —
	// was reached by no body and SILENTLY DROPPED.
	//
	// READ THIS BEFORE CHANGING THE SCOPING AGAIN. The two failure directions
	// are not symmetric. An INVENTED path is visible: it appears in the census
	// as a route nobody can find, and the coverage check demands an entry for
	// it. A DROPPED path reads as a clean sweep — the census is silent about
	// it, and every count agrees with itself. And a count cannot catch it
	// either: when this was written the tree derived 287 routes with the bug
	// and 287 without it, because nothing in it registers at package level, so an unchanged
	// number would have CERTIFIED the defect rather than exposed it. Only a
	// probe of the shape finds this class. Trading an invented path for a
	// dropped one is not a fix.
	//
	// Package level has no enclosing function, so there is no subrouter map and
	// nothing is shadowed: a bare identifier there IS the package-level
	// declaration.
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.FuncDecl:
			return false // already scanned, with its own scope
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			sel, ok := v.Fun.(*ast.SelectorExpr)
			if !ok || !routeMethods[sel.Sel.Name] || len(v.Args) == 0 {
				return true
			}
			// The same inverted default as the body walk. Package level has no
			// parameters, so the only names that reach the empty prefix are
			// proven package-level roots.
			prefix := unknownPrefix
			switch recv := sel.X.(type) {
			case *ast.Ident:
				// A package-level subrouter used in another package-level
				// initialiser: `var _ = pkgSub.HandleFunc("/child", nil)`.
				// Reading only the Subrouter() chain missed this and recorded
				// the child bare.
				// Two arms, as in the body walk. `prefix` already starts at
				// the sentinel, so an arm that assigns the sentinel to
				// something already holding it reads as a case somebody
				// thought about and decides nothing.
				switch {
				case isKnownSubrouter(pkgSubs, recv.Name):
					prefix = pkgSubs[recv.Name]
				case pkg.roots[recv.Name]:
					prefix = ""
				}
			default:
				if p, isSub := subrouterPrefix(sel.X, consts, dir, nil, pkgSubs, pkg.unfollowable, pkg.roots); isSub {
					prefix = p
				}
			}
			record(sel.Sel.Name, v.Args[0], v.Lparen, prefix, nil)
			return true
		}
		return true
	})
	return out
}

// boundNames returns the receiver, parameter and result names of a function.
//
// They are the shadowing case with a live near-miss on main: a parameter named
// like some other function's subrouter variable, or like a package constant.
func boundNames(recv *ast.FieldList, typ *ast.FuncType) map[string]bool {
	out := map[string]bool{}
	for _, fl := range []*ast.FieldList{recv, typ.Params, typ.Results} {
		if fl == nil {
			continue
		}
		for _, field := range fl.List {
			for _, name := range field.Names {
				out[name.Name] = true
			}
		}
	}
	return out
}

// packageScope is what a file needs from the REST of its package before it can
// be read correctly.
//
// All three were computed per FILE, which made them order-dependent in two
// ways: a package-level subrouter declared in one file and used in another was
// invisible, and one declared after its parent in the same file resolved
// against an empty map. Go has no such ordering, so neither can this.
type packageScope struct {
	subrouters   map[string]string
	methodValues map[string]RouteSite
	unfollowable map[string]bool
	// roots are package-level names PROVEN to be a plain router: declared
	// exactly once, with `mux.NewRouter()` as the value, and assigned nowhere
	// in any body. Under the round-8 rule a receiver is unknown unless it is
	// on a list, and this is the only way a package-level name reaches the
	// empty prefix.
	roots map[string]bool
}

// buildPackageScope collects the package-level declarations of every file in a
// directory, resolving subrouters to a FIXPOINT so a subrouter hanging off
// another resolves whichever order the two were declared in.
func buildPackageScope(files []parsedFile, dir string, consts map[string]string) packageScope {
	scope := packageScope{
		subrouters:   map[string]string{},
		methodValues: map[string]RouteSite{},
		unfollowable: map[string]bool{},
		roots:        map[string]bool{},
	}

	// EVERYTHING IS DECIDED UP FRONT, and poison is PERMANENT.
	//
	// The previous version discovered facts as it priced, so a name could be
	// priced in one round and poisoned in the next — and a third declaration
	// could toggle it back. Two rounds of review found leaks in exactly that
	// seam: a router declared `var x *mux.Router` and assigned inside init()
	// was never seen as a subrouter at all and was priced from the root, and a
	// twin's sentinel flipped per round instead of sticking.
	//
	// So the sets are computed before any pricing, from the complete package
	// rather than as the walk discovers them.
	//
	// ROUND 8 INVERTED THE DEFAULT, and that is the change that matters.
	//
	// Seven rounds of review each enumerated one more shape to poison, and each
	// time the next round found the shape that enumeration had missed: assigned
	// in a body, declared twice by build-tag twins, aliased, built on an
	// unfollowable receiver, indexed out of a slice, ranged over, read from a
	// map. Enumerating what to REFUSE cannot terminate, because the author of
	// the list is the same person who decided what the list is about.
	//
	// So a receiver is now UNKNOWN unless it is on a list of shapes each of
	// which has a fixture and a survivor pin:
	//
	//	(a) a function parameter — the stated assumption that a router handed
	//	    to a function is a plain one;
	//	(b) a local `:=`/`var` whose right-hand side is a PathPrefix/NewRoute
	//	    chain rooted in an already-priced receiver in the SAME body, or
	//	    `mux.NewRouter()`;
	//	(c) a package-level name whose single ValueSpec value is such a chain
	//	    rooted in `var x = mux.NewRouter()` or another priced package-level
	//	    name — resolved to a fixpoint over ALL files of the package before
	//	    any body is walked, so file order cannot decide the answer;
	//	(d) the immediate chained form, `r.PathPrefix(P).Subrouter().HandleFunc(...)`.
	//
	// Everything else is reported: aliased, indexed, ranged, a call result, a
	// struct field, a twin, a parameter that is reassigned. The cost of the
	// inversion is that a shape nobody has thought of reads as an unknown
	// rather than as a route, which is the direction that cannot invent a URL.
	type candidate struct {
		values []ast.Expr
		file   parsedFile
	}
	cands := map[string]*candidate{}
	assignedInBody := map[string]bool{}
	isSubrouterExpr := func(e ast.Expr) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "Subrouter"
	}
	// `mux.NewRouter()` — the only expression that proves a plain router. A
	// bare `NewRouter()` (dot-import) counts; anything else, including a
	// helper that returns one, does not: the whole point of the inversion is
	// that "probably a router" is not on the list.
	isNewRouterExpr := func(e ast.Expr) bool {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return false
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			return fn.Sel.Name == "NewRouter"
		case *ast.Ident:
			return fn.Name == "NewRouter"
		}
		return false
	}

	for _, pf := range files {
		// Package-level declarations, values or not. A `var x *mux.Router` with
		// NO value is exactly the R6-1 shape: nothing to price, and something
		// elsewhere assigns it.
		for _, decl := range pf.file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					c := cands[name.Name]
					if c == nil {
						c = &candidate{file: pf}
						cands[name.Name] = c
					}
					if i < len(vs.Values) {
						c.values = append(c.values, vs.Values[i])
						if mv, isSel := vs.Values[i].(*ast.SelectorExpr); isSel && routeMethods[mv.Sel.Name] {
							scope.methodValues[name.Name] = RouteSite{
								Method:  mv.Sel.Name,
								File:    pf.rel,
								Edition: pf.edition,
								Expr: "a method VALUE of a route method (" + exprText(vs.Values[i]) +
									"), invoked as a function; the route it registers is one " +
									"this scanner cannot see",
							}
						}
					} else {
						// Declared with no value: unprovable here by
						// construction.
						c.values = append(c.values, nil)
					}
				}
			}
		}
		// Every assignment anywhere, at any depth. Two things come from it: a
		// name assigned in a body can never be priced from its declaration,
		// and a Subrouter() bound to something other than a plain identifier
		// is an unfollowable home.
		ast.Inspect(pf.file, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			// `:=` ONLY EVER BINDS A LOCAL, so it says nothing about the
			// package-level name it may share a spelling with. Recording it
			// here keyed by name meant one unrelated `shared := other()`
			// anywhere in the package took the prefix off a package-level
			// `shared` that nothing had touched — over-poisoning, the safe
			// direction, and still a real route losing its prefix.
			//
			// A package-level declaration cannot use `:=`, so nothing is lost
			// by skipping them: every assignment that can rebind a
			// package-level name is a plain `=`.
			if as.Tok == token.DEFINE {
				return true
			}
			for i, rhs := range as.Rhs {
				if i >= len(as.Lhs) {
					break
				}
				if id, plain := as.Lhs[i].(*ast.Ident); plain {
					// Recording the assignment is ALL that happens here. An
					// earlier version also poisoned the name on the spot, but
					// only `if _, known := cands[id.Name]; known` — so whether
					// it fired depended on which FILE the walk had reached,
					// which is the order-dependence round 7 reproduced. The
					// classifier below now decides every name from the
					// complete sets, so the line was redundant as well as
					// order-dependent.
					assignedInBody[id.Name] = true
					continue
				}
				if isSubrouterExpr(rhs) {
					scope.unfollowable[exprText(as.Lhs[i])] = true
				}
			}
			return true
		})
	}

	// Classify. A name is a candidate for pricing only when it has EXACTLY one
	// ValueSpec value, that value is a Subrouter chain, and nothing assigns the
	// name in a body. Anything else that is router-shaped is poisoned now and
	// stays poisoned.
	priceable := map[string]ast.Expr{}
	for name, c := range cands {
		var subValues, rootValues []ast.Expr
		for _, v := range c.values {
			if v == nil {
				continue
			}
			if isSubrouterExpr(v) {
				subValues = append(subValues, v)
			}
			if isNewRouterExpr(v) {
				rootValues = append(rootValues, v)
			}
		}
		// A PROVEN package-level root: declared once, `mux.NewRouter()`,
		// assigned nowhere. Only this reaches the empty prefix.
		if len(rootValues) == 1 && len(c.values) == 1 && !assignedInBody[name] {
			scope.roots[name] = true
			continue
		}
		if len(subValues) == 1 && len(c.values) == 1 && !assignedInBody[name] {
			priceable[name] = subValues[0]
			continue
		}
		// AND THERE IS NO THIRD ARM. A name that is router-shaped and could
		// not be priced — build-tag twins, a valueless declaration beside a
		// chain, a reassignment — simply does not enter `roots` or
		// `priceable`, and the inverted default at every call site reports it.
		//
		// Two earlier drafts each added a second mechanism here: a `pending`
		// set, and a poison keyed on the declared TYPE. Both were made
		// redundant by the inversion, and both could be deleted with the whole
		// suite green and the tree derivation byte-identical at 284 routes and
		// 8 unresolved — five mutants of them survived for exactly that
		// reason. Worse than redundant, `pending` was consulted BEFORE the
		// caller's own map, so a local `sub := mux.NewRouter()` sharing a
		// spelling with a disqualified package-level name was refused a prefix
		// it had proved. Two mechanisms covering one property make each
		// other's mutants survive, and one of them is usually also wrong.
	}

	// Price to a fixpoint. A receiver is acceptable only when it is already
	// priced, or when it is not a package-level router at all (a plain root).
	// Nothing else resolves, which is the whole of rule 1.
	names := make([]string, 0, len(priceable))
	for name := range priceable {
		names = append(names, name)
	}
	// SORTED, because map iteration order is random and the fixpoint's
	// intermediate states depend on it. Without this a mutant that cuts the
	// round bound kills on some runs and not others, which is worse than a
	// survivor: a flaky kill is read as a flaky test and the pin is deleted.
	sort.Strings(names)
	for round := 0; round <= len(priceable)+1; round++ {
		changed := false
		for _, name := range names {
			expr := priceable[name]
			if _, done := scope.subrouters[name]; done {
				continue
			}
			prefix, isSub := subrouterPrefix(expr, consts, dir, nil, scope.subrouters, scope.unfollowable, scope.roots)
			if !isSub || prefix == unknownPrefix {
				continue
			}
			scope.subrouters[name] = prefix
			changed = true
		}
		if !changed {
			break
		}
	}
	return scope
}

// isNewRouterCall reports whether an expression is `mux.NewRouter()`.
//
// It is the body-level twin of the package-level check, and it is deliberately
// the same narrow shape: a helper that returns a router is not recognised,
// because "returns a router" and "returns a SUBrouter with a prefix" are the
// same syntax and only one of them can be priced at "/".
func isNewRouterCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		return fn.Sel.Name == "NewRouter"
	case *ast.Ident:
		return fn.Name == "NewRouter"
	}
	return false
}

// isKnownSubrouter distinguishes "absent from the map" from "present with an
// empty prefix", which `known[name] != ""` cannot.
//
// A subrouter built by `NewRoute().Subrouter()` has the empty prefix and is
// perfectly well known; reading the map bare would treat it as unknown and
// report every one of its children.
func isKnownSubrouter(known map[string]string, name string) bool {
	_, ok := known[name]
	return ok
}

// subrouterPrefix recognises `<x>.PathPrefix(P).Subrouter()` and
// `<x>.NewRoute().Subrouter()` and returns the full prefix.
//
// IT RESOLVES ITS RECEIVER, which the first version did not. A subrouter can
// hang off another subrouter — `b := a.PathPrefix("/y").Subrouter()` where `a`
// is already `/x` — and reading only the argument gives `/y`, so `b`'s children
// come out at `/y/z` instead of `/x/y/z`: a top-level route the server does not
// serve. The poison stopped at one level for the same reason: an unresolvable
// OUTER prefix left the inner one looking perfectly readable.
//
// known maps identifiers to the prefixes already learned in this scope. It may
// be nil, which is the package-level and const-collection case.
func subrouterPrefix(e ast.Expr, consts map[string]string, dir string,
	shadowed map[string]bool, known map[string]string,
	unfollowable map[string]bool, roots map[string]bool) (string, bool) {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Subrouter" {
		return "", false
	}
	// From here the expression IS a Subrouter() call, so every exit is either a
	// price or an admitted UNKNOWN — never a "not a subrouter". Returning false
	// here left the name unlearned, and a registration on an unlearned name is
	// priced from the root: `f().Subrouter()`, a parenthesised chain and
	// `route.Subrouter()` on a Route rather than a Router all came out bare.
	inner, ok := sel.X.(*ast.CallExpr)
	if !ok {
		return unknownPrefix, true
	}
	innerSel, ok := inner.Fun.(*ast.SelectorExpr)
	if !ok {
		return unknownPrefix, true
	}
	// The receiver of NewRoute()/PathPrefix(): a router, or another subrouter.
	// An unreadable receiver poisons the whole chain rather than being treated
	// as the root, which is what makes the poison propagate through nesting.
	base, baseKnown := unknownPrefix, true
	switch recv := innerSel.X.(type) {
	case *ast.Ident:
		// THE INVERTED DEFAULT. `base` starts UNKNOWN and only a name on the
		// list moves it. Before round 8 it started at the empty string, so
		// every identifier the three lookups below did not recognise was
		// silently the root — which is how an alias, an unassigned var, a
		// parameter that had been reassigned and a name declared in another
		// file each came out at "/", one round of review apart.
		//
		// Two arms, and there is no third. A name the CALLER proved, then a
		// proven root. Everything else keeps the sentinel `base` started with.
		switch {
		case isKnownSubrouter(known, recv.Name):
			base = known[recv.Name]
		case roots[recv.Name]:
			// (c): a package-level `var x = mux.NewRouter()`, proven.
			base = ""
		}
	default:
		// An UNFOLLOWABLE home heading a chain: `s.sub.PathPrefix("/p")
		// .Subrouter()`. The receiver is a subrouter whose prefix nobody can
		// read, so the chain built on it cannot be priced either — it was
		// coming out at "/p".
		if unfollowable[exprText(innerSel.X)] {
			base = unknownPrefix
		} else if p, isSub := subrouterPrefix(innerSel.X, consts, dir, shadowed, known, unfollowable, roots); isSub {
			base = p
		}
		// Every other receiver — a call result, an index expression, a struct
		// field, a parenthesised anything — keeps the unknown `base` it
		// started with. There is no arm to add here; that is the point of the
		// inversion.
	}
	if base == unknownPrefix {
		baseKnown = false
	}
	switch innerSel.Sel.Name {
	case "NewRoute":
		if !baseKnown {
			return unknownPrefix, true
		}
		return base, true
	case "PathPrefix":
		if len(inner.Args) != 1 {
			return "", false
		}
		if s, ok := staticStringScoped(inner.Args[0], consts, dir, shadowed); ok {
			if !baseKnown {
				return unknownPrefix, true
			}
			return base + s, true
		}
		// The prefix exists but is unknown, so every registration on this
		// subrouter is unknown too. Returning false would silently treat them
		// as top-level paths; the sentinel makes every child unresolved.
		return unknownPrefix, true
	default:
		// `r.Path("/x").Subrouter()`, `r.Methods(...).Subrouter()`, anything
		// else: this scanner cannot say what region of the URL space the
		// result covers, so it refuses to. Reporting is the contract; guessing
		// the root is how a child comes out bare.
		return unknownPrefix, true
	}
}

func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Value
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return exprText(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return exprText(v.Fun) + "(...)"
	case *ast.BinaryExpr:
		return exprText(v.X) + " + " + exprText(v.Y)
	case *ast.ParenExpr:
		return "(" + exprText(v.X) + ")"
	default:
		return fmt.Sprintf("%T", e)
	}
}

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// SiteKey is the stable identifier of one route-registration call site, used
// by the registry's route_exemptions. It names the file, the line, the method
// and the expression, because all four are what a reviewer needs in order to
// decide whether an exemption is still deserved.
func (s RouteSite) SiteKey() string {
	return fmt.Sprintf("%s:%d %s(%s)", s.File, s.Line, s.Method, s.Expr)
}

// goFilesUnder returns the repo-relative non-test Go files at or under a
// repo-relative path, which may be a single file or a directory.
//
// A path that does not exist returns no files and NO error, because the
// community mirror legitimately lacks the enterprise paths an entry names.
// Callers that need the distinction check for the tree themselves; making this
// function fail there would turn the mirror's correct behaviour into a red
// test in the public repository.
func goFilesUnder(root, rel string) ([]string, error) {
	full := filepath.Join(root, rel)
	info, err := os.Stat(full)
	if err != nil {
		return nil, nil
	}
	if !info.IsDir() {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil, nil
		}
		return []string{rel}, nil
	}
	var out []string
	err = filepath.WalkDir(full, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case "testdata", "node_modules", ".git", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		r, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		out = append(out, filepath.ToSlash(r))
		return nil
	})
	sort.Strings(out)
	return out, err
}

// DeriveEditionFacts reads a capability's build tag and mirror disposition off
// the TREE, from the files its implementation names.
//
// It exists because the classification rules that only look at the registry can
// be satisfied by editing the registry. An enterprise capability laundered into
// the community column - classification community_core, build_tag none, sync
// mirrored, scored available to Community - is internally consistent and passes
// every check that reads the document alone. The tree is what makes it a lie,
// and the tree is checkable: circuit.breaker names a file carrying
// `//go:build enterprise`, so no amount of editing the row makes that row true.
//
// Returns the tag and sync a correct entry must declare, and whether anything
// was found at all. `found` is false when none of the paths exist, which is the
// community mirror's normal state for an excluded capability and is NOT an
// error - the caller decides, because only the caller knows which tree it is
// looking at.
func DeriveEditionFacts(root string, implementation []string) (BuildTag, Sync, bool, error) {
	var enterprise, community int
	var found bool
	for _, impl := range implementation {
		files, ferr := goFilesUnder(root, impl)
		if ferr != nil {
			return "", "", false, ferr
		}
		for _, f := range files {
			found = true
			ed, eerr := SourceEdition(root, f)
			if eerr != nil {
				return "", "", false, eerr
			}
			if ed == "enterprise" {
				enterprise++
				continue
			}
			community++
		}
	}
	if !found {
		return "", "", false, nil
	}
	switch {
	case enterprise == 0:
		return TagNone, SyncMirrored, true, nil
	case community == 0:
		// Every file the mirror strips: nothing of this capability survives it.
		return TagEnterprise, SyncExcluded, true, nil
	default:
		// Both halves present. The mirror receives the community half, which is
		// a stub or a reduced implementation, never the operational one.
		return TagSplit, SyncStub, true, nil
	}
}
