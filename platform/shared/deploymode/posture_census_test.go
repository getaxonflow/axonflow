// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package deploymode

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// THE CENSUS OF SECOND READINGS (#3713)
//
// This lives in a _test.go file, so go/parser and a tree walk never reach a
// shipped binary. It is split into a SCAN half (scanPosturereadings, which
// reads the real tree) and a pure DECISION half (classifyreadings, below the
// guard), for the reason platform/shared/identity/compat_env_reader_test.go
// gives: a census that reads source FROM DISK cannot be killed by a
// `go test -overlay` mutant, because the overlay changes what the COMPILER
// sees and never what os.ReadFile returns. A guard with no demonstrated
// failing input is indistinguishable from one whose extraction silently
// returns nothing, so the shapes it must report are planted here instead.
//
// # WHAT IT LOOKS FOR, AND WHY NOT WHAT THE LINT LOOKS FOR
//
// scripts/lint-deployment-mode.sh already flags a direct
// os.Getenv("DEPLOYMENT_MODE") outside an allow-list. That is a check on the
// SPELLING of the env read, and it is defeated by every derivation that does
// not spell it: a value obtained from deploymode.Current(), passed into a
// helper as a parameter, or normalised through strings.ToLower first, all pass
// the lint silently. Four of the readings #3713 found would have been reported
// by it; the fifth - platform/shared/policy's `mode != "community" && mode !=
// ""`, which answers the OPPOSITE thing for an unset value - is a comparison
// the lint has no opinion about at all, because reading the variable is not
// what is wrong with it.
//
// So this asks a different question: WHERE DOES A DEPLOYMENT_MODE VALUE MEET A
// MODE NAME? That is the shape of every re-derivation, whatever route the
// value took, and it is the shape of none of the legitimate uses (which either
// pass the value to this package, or log it).
//
// # THE SET OF MODE NAMES IS DERIVED, NOT LISTED
//
// It is RecognisedModes() plus the empty string. A guard carrying its own list
// of four call sites - or its own list of mode names - is a guard that goes
// stale the day a mode is added, which is the failure mode of every other copy
// this package exists to remove.
// ---------------------------------------------------------------------------

// deploymodeImportPath is this package's import path. A file that reads the
// mode through this package is asking the question the right way; a file that
// COMPARES the result to a mode name is asking it again.
const deploymodeImportPath = "axonflow/platform/shared/deploymode"

// reading is one place where a DEPLOYMENT_MODE-derived value meets a mode name.
type reading struct {
	// File is slash-separated and relative to the scan root, so a finding reads
	// the same on every machine and in every CI runner.
	File string
	// Func is the enclosing function, or "" for a package-level declaration.
	// A METHOD is spelled "ReceiverType.Method".
	//
	// It is what an exemption is KEYED on, and keying on the file alone was a
	// hole R3 proved with a compiling plant: five files are on both this
	// census's exemption list and scripts/lint-deployment-mode.sh's allow-list,
	// so a brand-new raw `os.Getenv("DEPLOYMENT_MODE") == "community"` appended
	// to any of them passed BOTH instruments. The exemption reasons are all
	// per-FUNCTION - "devTokenEndpointEnabled normalises", "getMigrationPaths is
	// the schema selector" - so a second reading elsewhere in the same file is a
	// different finding wearing the first one's exemption.
	Func string
	Line int
	// Shape names the syntax the value was compared with: "==", "!=", "switch"
	// or "call". It is reported so an exemption can say what it exempts.
	Shape string
	// Detail is the mode name(s) the value was compared against.
	Detail string
}

func (r reading) String() string {
	fn := r.Func
	if fn == "" {
		fn = "<package-level>"
	}
	return fmt.Sprintf("%s:%d %s() [%s] a DEPLOYMENT_MODE value meets %s", r.File, r.Line, fn, r.Shape, r.Detail)
}

// key is what an exemption names: the file and the enclosing function.
func (r reading) key() string { return r.File + "#" + r.Func }

// postureCensus is the result of one scan.
type postureCensus struct {
	// Files is the number of non-test Go files parsed. Zero means the walk is
	// broken, not that the tree is clean.
	Files int
	// Seeds is the number of DEPLOYMENT_MODE-derived expressions found, before
	// any comparison is considered. Zero means the seed recognisers stopped
	// matching - the single most likely way this census goes silently blind -
	// and it is a distinct signal from "no comparisons".
	Seeds int
	// readings is every site found, sorted by file then line.
	readings []reading
	// MissingRoots are scan roots that did not exist. On the community mirror
	// `ee/` is stripped wholesale, so its absence is expected rather than an
	// error, and the staleness half has to know which paths it cannot judge.
	MissingRoots []string
}

// modeNames is the set of string literals that count as "a mode name": every
// recognised spelling, plus the empty string.
//
// The empty string is in the set BECAUSE of platform/shared/policy's
// `mode != "community" && mode != ""`. Comparing the variable against "" is
// how a call site decides what an unconfigured deployment gets, and that is
// exactly the decision #3096 and #3128 are about. A census that only looked for
// mode NAMES would report the `"community"` half of that expression and stay
// silent about the half that makes it disagree with everything else.
func modeNames() map[string]bool {
	out := map[string]bool{}
	for _, m := range RecognisedModes() {
		out[m] = true
	}
	return out
}

// unsetLiteral is a mode name only in a COMPARISON, never as an argument.
//
// `mode == ""` decides what an unconfigured deployment gets, which is the whole
// content of #3096 and #3128, so a census blind to it would miss the one
// reading whose ANSWER differs rather than only its spelling. But `""` is also
// the commonest string literal in Go: logger.Sanitize's
// `strings.ReplaceAll(s, "\x00", "")` put three unrelated packages in the
// report the first time this ran. So it is admitted where it is a decision and
// refused where it is punctuation.
const unsetLiteral = ""

// skipDirs are directories with no first-party Go source in them.
var skipDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, "testdata": true,
	".claude": true, "dist": true, "build": true,
}

// scanPostureReadings parses every non-test Go file under each root and reports
// every site where a DEPLOYMENT_MODE-derived value meets a mode name.
//
// Roots are relative to base. A root that does not exist is recorded in
// MissingRoots rather than failing: the community mirror strips `ee/`.
func scanPostureReadings(base string, roots []string) (postureCensus, error) {
	var census postureCensus

	type parsedFile struct {
		rel  string
		dir  string
		pkg  string
		fset *token.FileSet
		file *ast.File
	}
	var files []parsedFile

	for _, root := range roots {
		abs := filepath.Join(base, root)
		if _, err := os.Stat(abs); err != nil {
			census.MissingRoots = append(census.MissingRoots, root)
			continue
		}
		walkErr := filepath.WalkDir(abs, func(fpath string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // an unreadable subtree is not this census's business
			}
			if d.IsDir() {
				if skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			name := d.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			// go/parser does NOT evaluate build constraints, so both halves of
			// every //go:build pair are parsed. That is required rather than
			// incidental: an enterprise-tagged file is exactly where a second
			// reading would be least visible to a community-tagged CI lane.
			f, perr := parser.ParseFile(fset, fpath, nil, 0)
			if perr != nil {
				return nil // a file that does not parse is not evidence either way
			}
			rel, rerr := filepath.Rel(base, fpath)
			if rerr != nil {
				rel = fpath
			}
			slashRel := filepath.ToSlash(rel)
			files = append(files, parsedFile{
				rel:  slashRel,
				dir:  path.Dir(slashRel),
				pkg:  f.Name.Name,
				fset: fset,
				file: f,
			})
			return nil
		})
		if walkErr != nil {
			return census, walkErr
		}
	}
	census.Files = len(files)

	dirSet := map[string]bool{}
	for _, pf := range files {
		dirSet[pf.dir] = true
	}
	dirsByTail := indexDirsByTail(dirSet)

	names := modeNames()

	// PASS 1: every string constant in the corpus, by name. A comparison
	// against a NAMED constant whose value is a mode name is the same
	// re-derivation as one against the literal - platform/shared/corspolicy
	// wrote it that way, with `communityMode = "community"` beside the read, so
	// a literal-only census would have missed the copy #3713 is named for.
	//
	// Keyed by the bare identifier: a qualified `pkg.CommunityMode` and an
	// unqualified `CommunityMode` are the same declaration seen from two
	// packages, and resolving imports to tell two same-named constants in
	// different packages apart would buy precision this census does not need.
	// The cost of the over-approximation is a report that has to be exempted;
	// the cost of the under-approximation is silence.
	constValues := map[string]string{}
	for _, pf := range files {
		for _, decl := range pf.file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, id := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if s, ok := stringLit(vs.Values[i]); ok {
						constValues[id.Name] = s
					}
				}
			}
		}
	}

	// PASS 2: the interprocedural fixpoint. `tainted` holds functions whose
	// Nth parameter receives a DEPLOYMENT_MODE value at some call site, keyed
	// "name/index". It grows until it stops growing, because the value can be
	// handed on: ee/platform/customer-portal/main.go reads the variable, passes
	// it to ShouldProvisionDeploymentOrgPassword, and the comparison lives
	// there - two frames from the read, which is why one pass is not enough.
	//
	// Functions are keyed by NAME, not by package. Two same-named functions in
	// different packages are conflated, which can only ever ADD reports.
	tainted := map[string]bool{}
	for iteration := 0; ; iteration++ {
		grew := false
		for _, pf := range files {
			an := &analyser{
				rel:          pf.rel,
				dir:          pf.dir,
				fset:         pf.fset,
				names:        names,
				consts:       constValues,
				tainted:      tainted,
				modePkgs:     deploymodeLocalNames(pf.file),
				imports:      importDirs(pf.file, dirsByTail),
				inDeploymode: pf.pkg == "deploymode",
			}
			an.run(pf.file)
			for k := range an.newTaint {
				if !tainted[k] {
					tainted[k] = true
					grew = true
				}
			}
		}
		if !grew {
			break
		}
		// A cap, so a pathological corpus cannot spin. Reaching it means the
		// fixpoint did not converge, which is a bug in this analysis rather
		// than a fact about the tree - so it is reported, never swallowed.
		if iteration > 16 {
			return census, fmt.Errorf("the taint fixpoint did not converge in %d iterations; "+
				"this census is broken, and a broken census reports a clean tree", iteration)
		}
	}

	// PASS 3: collect, with the taint set now closed.
	seen := map[string]bool{}
	for _, pf := range files {
		an := &analyser{
			rel:          pf.rel,
			dir:          pf.dir,
			fset:         pf.fset,
			names:        names,
			consts:       constValues,
			tainted:      tainted,
			modePkgs:     deploymodeLocalNames(pf.file),
			imports:      importDirs(pf.file, dirsByTail),
			inDeploymode: pf.pkg == "deploymode",
			collect:      true,
		}
		an.run(pf.file)
		census.Seeds += an.seeds
		for _, r := range an.readings {
			key := fmt.Sprintf("%s:%d:%s:%s", r.File, r.Line, r.Shape, r.Detail)
			if seen[key] {
				continue
			}
			seen[key] = true
			census.readings = append(census.readings, r)
		}
	}
	sort.Slice(census.readings, func(i, j int) bool {
		if census.readings[i].File != census.readings[j].File {
			return census.readings[i].File < census.readings[j].File
		}
		if census.readings[i].Line != census.readings[j].Line {
			return census.readings[i].Line < census.readings[j].Line
		}
		return census.readings[i].Detail < census.readings[j].Detail
	})
	return census, nil
}

// deploymodeLocalNames returns the local identifiers this file binds to this
// package's import path - the default `deploymode`, plus any alias. A file that
// does not import it gets an empty set, and `deploymode.Current()` written
// there is then some other package's Current, which is not a seed.
func deploymodeLocalNames(f *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != deploymodeImportPath {
			continue
		}
		if imp.Name != nil {
			out[imp.Name.Name] = true
			continue
		}
		out["deploymode"] = true
	}
	return out
}

// importDirs maps each local qualifier in f to the DIRECTORIES of the package
// it names, so a call written `api.Foo(...)` keys the same taint entries that
// `func Foo` in that package declares.
//
// # AN IMPORT PATH IS NOT A DIRECTORY IN THIS TREE, AND ASSUMING IT WAS LOST A
// # SITE SILENTLY
//
// The first version stripped the leading "axonflow/" and used the rest as the
// directory. That is true for axonflow/platform/..., and FALSE for the
// customer-portal: ee/go.mod carries `replace axonflow/platform/customer-portal
// => ./platform/customer-portal`, so the portal's own main.go imports
// `axonflow/platform/customer-portal/api` for a package that lives at
// ee/platform/customer-portal/api. Four modules in this tree use replace
// directives that way.
//
// The cost was not an error. The census simply reported one site fewer, which
// is indistinguishable from a clean tree - the same null result a surviving
// mutant gives. So the mapping is now empirical: match the import path's tail
// against the directories actually scanned. A path that matches several
// directories yields all of them, because over-approximating adds a report an
// exemption can answer, while under-approximating adds silence nobody can see.
func importDirs(f *ast.File, dirsByTail map[string][]string) map[string][]string {
	out := map[string][]string{}
	for _, imp := range f.Imports {
		ip, err := strconv.Unquote(imp.Path.Value)
		if err != nil || !strings.HasPrefix(ip, "axonflow/") {
			continue
		}
		tail := strings.TrimPrefix(ip, "axonflow/")
		dirs := dirsByTail[tail]
		if len(dirs) == 0 {
			continue
		}
		name := path.Base(tail)
		if imp.Name != nil {
			name = imp.Name.Name
		}
		out[name] = dirs
	}
	return out
}

// indexDirsByTail maps every path-suffix of every scanned directory to the
// directories that carry it, so an import path's tail resolves in one lookup.
func indexDirsByTail(dirs map[string]bool) map[string][]string {
	out := map[string][]string{}
	for d := range dirs {
		segs := strings.Split(d, "/")
		for i := range segs {
			tail := strings.Join(segs[i:], "/")
			out[tail] = append(out[tail], d)
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// analyser walks one file. Fields are the corpus-wide inputs; readings,
// newTaint and seeds are its output.
type analyser struct {
	rel      string
	fset     *token.FileSet
	names    map[string]bool
	consts   map[string]string
	tainted  map[string]bool
	modePkgs map[string]bool
	// dir is this file's directory, slash-separated and relative to the scan
	// base. It is the package identity used to key taint, so two same-named
	// functions in different packages are not conflated.
	dir string
	// imports maps a local qualifier to the DIRECTORY of the package it names,
	// so a qualified call resolves to the same key its declaration produces.
	imports map[string][]string
	// inDeploymode is true for this package's own files, where an unqualified
	// Current() is the env read. Elsewhere Current() belongs to somebody else -
	// planeshadow and identity both have one - and treating it as a seed put
	// four unrelated packages in the first report.
	inDeploymode bool
	collect      bool

	// boolCalls are the CallExprs whose RESULT is consumed as a condition.
	// See the call shape in visit for why that, and not a list of function
	// names, is what separates a comparison from a log line.
	boolCalls map[ast.Node]bool

	readings []reading
	newTaint map[string]bool
	seeds    int

	// local is the set of identifiers holding a mode value in the function
	// currently being walked.
	local map[string]bool
	// fileLocal is the set of PACKAGE-LEVEL identifiers holding a mode value.
	// Every function body inherits it.
	//
	// An earlier version claimed the ordinary assignment handler covered this
	// "because it runs first". Neither half was true - run() reset local at
	// every declaration, and declarations are walked in source order, so a var
	// declared below a function was never seen by it. R3 found the gap by
	// planting it; the comment would have defended it from the next reader.
	fileLocal map[string]bool
	// nameLocal is the set of identifiers holding a MODE NAME rather than a
	// mode VALUE - a loop variable ranging over a literal list of mode names,
	// which is how a whole taxonomy gets restated without a single literal
	// appearing beside the comparison.
	nameLocal map[string]bool
	// nameMaps are identifiers assigned from a map literal keyed by mode names.
	nameMaps map[string]bool
	// nameLists are identifiers assigned from a slice literal OF mode names.
	nameLists map[string]bool
	// fileNameMaps / fileNameLists are the PACKAGE-LEVEL forms of the two
	// above. Every function body inherits them.
	fileNameMaps  map[string]bool
	fileNameLists map[string]bool
	// curFunc is the function being walked.
	curFunc string
}

func (a *analyser) run(f *ast.File) {
	a.newTaint = map[string]bool{}

	// PASS A over this file: package-level `var x = os.Getenv("DEPLOYMENT_MODE")`.
	// Done in its own pass, before any function body, because a var may be
	// declared BELOW the function that reads it and source order is not
	// something a finding may depend on.
	a.fileLocal = map[string]bool{}
	a.fileNameMaps = map[string]bool{}
	a.fileNameLists = map[string]bool{}
	a.local = a.fileLocal
	a.nameLocal = map[string]bool{}
	a.nameMaps = map[string]bool{}
	a.nameLists = map[string]bool{}
	a.boolCalls = map[ast.Node]bool{}
	a.curFunc = ""
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
			for i, id := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if a.isModeValue(vs.Values[i]) {
					a.fileLocal[id.Name] = true
				}
				// A package-level taxonomy - `var allowedModes = map[...]` or
				// `var modeList = []string{...}` - is file-scoped for the same
				// reason a package-level mode value is: the function that reads
				// it may be declared above it, and source order must not decide
				// a finding.
				if a.isModeNameKeyedMap(vs.Values[i]) {
					a.fileNameMaps[id.Name] = true
				}
				if a.isModeNameList(vs.Values[i]) {
					a.fileNameLists[id.Name] = true
				}
			}
		}
	}

	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			// A package-level declaration can also CONTAIN a comparison, in an
			// initialiser expression.
			a.local = copySet(a.fileLocal)
			a.nameLocal = map[string]bool{}
			a.nameMaps = copySet(a.fileNameMaps)
			a.nameLists = copySet(a.fileNameLists)
			a.nameLists = map[string]bool{}
			a.curFunc = ""
			a.boolCalls = map[ast.Node]bool{}
			markBooleanConsumed(decl, a.boolCalls)
			ast.Inspect(decl, a.visit)
			continue
		}
		a.curFunc = funcIdent(fd)
		a.local = copySet(a.fileLocal)
		a.nameLocal = map[string]bool{}
		a.nameMaps = copySet(a.fileNameMaps)
		a.nameLists = copySet(a.fileNameLists)
		a.boolCalls = map[ast.Node]bool{}
		markBooleanConsumed(fd, a.boolCalls)
		// A parameter of a function that RECEIVES a mode value anywhere in the
		// corpus is itself a mode value here.
		if fd.Type.Params != nil {
			idx := 0
			for _, field := range fd.Type.Params.List {
				for _, id := range field.Names {
					// A PARAMETER SHADOWS a package-level name, so inheriting
					// the file-scoped taint for it would attribute a reading to
					// a function that never sees the mode - and the exemption
					// somebody then writes would name the wrong function.
					delete(a.local, id.Name)
					if a.tainted[a.taintKey(a.curFunc, idx)] {
						a.local[id.Name] = true
					}
					idx++
				}
				if len(field.Names) == 0 {
					idx++
				}
			}
		}
		// Two walks: the first settles which locals hold a mode value (an
		// assignment can textually follow a use inside a closure), the second
		// judges. One walk would make the analysis order-dependent, and a
		// finding that depends on statement order is a finding that moves when
		// somebody reformats.
		saved := a.collect
		a.collect = false
		ast.Inspect(fd, a.visit)
		a.collect = saved
		ast.Inspect(fd, a.visit)
	}
}

// taintKey identifies a parameter position of a function DECLARED in this
// file's package.
// funcIdent names a declaration for an exemption key. A METHOD carries its
// RECEIVER TYPE, because the bare method name is not unique in a package.
//
// Round 1 narrowed the exemption key from the file to the function, after a
// compiling plant showed a fresh raw read in an exempt FILE passed both this
// census and the lint. Round 2 then showed the fix was still one level too
// wide: a METHOD named devTokenEndpointEnabled on any type in that file wore
// the exemption written for the FUNCTION of that name, and was silently
// admitted - proven with a compiling plant, whose control (the same method
// under a different name) was reported. Three exempted files contain methods,
// so the hole was live in kind.
func funcIdent(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	return receiverTypeName(fd.Recv.List[0].Type) + "." + fd.Name.Name
}

// receiverTypeName renders T, *T and generic T[P] alike as "T".
func receiverTypeName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		return receiverTypeName(x.X)
	case *ast.IndexExpr:
		return receiverTypeName(x.X)
	case *ast.IndexListExpr:
		return receiverTypeName(x.X)
	}
	return "?"
}

func copySet(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (a *analyser) taintKey(fn string, idx int) string {
	return a.dir + "." + fn + "/" + strconv.Itoa(idx)
}

// callTaintKey identifies the parameter position a CALL fills. An unqualified
// call resolves in this package; a qualified one resolves through the import
// map. A selector whose qualifier is NOT an import is a method on a value, and
// this analysis does not follow those - stated here rather than left implicit,
// because it is the one route by which a mode value could reach a comparison
// unseen.
func (a *analyser) callTaintKeys(x *ast.CallExpr, idx int) ([]string, bool) {
	switch fn := x.Fun.(type) {
	case *ast.Ident:
		return []string{a.dir + "." + fn.Name + "/" + strconv.Itoa(idx)}, true
	case *ast.SelectorExpr:
		q, ok := fn.X.(*ast.Ident)
		if !ok {
			return nil, false
		}
		dirs, ok := a.imports[q.Name]
		if !ok {
			return nil, false
		}
		keys := make([]string, 0, len(dirs))
		for _, dir := range dirs {
			keys = append(keys, dir+"."+fn.Sel.Name+"/"+strconv.Itoa(idx))
		}
		return keys, true
	}
	return nil, false
}

// markBooleanConsumed records every CallExpr whose result is used as a
// condition: an if/for guard, an operand of && or || or !, or a returned
// value. Nothing here names a function.
func markBooleanConsumed(root ast.Node, out map[ast.Node]bool) {
	mark := func(e ast.Expr) {
		if e == nil {
			return
		}
		ast.Inspect(e, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				out[c] = true
			}
			return true
		})
	}
	ast.Inspect(root, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.IfStmt:
			mark(x.Cond)
		case *ast.ForStmt:
			mark(x.Cond)
		case *ast.ReturnStmt:
			for _, r := range x.Results {
				mark(r)
			}
		case *ast.UnaryExpr:
			if x.Op == token.NOT {
				mark(x.X)
			}
		case *ast.BinaryExpr:
			if x.Op == token.LAND || x.Op == token.LOR {
				mark(x.X)
				mark(x.Y)
			}
		case *ast.CaseClause:
			// A TAGLESS switch's case expressions ARE conditions:
			//
			//	switch {
			//	case strings.EqualFold(mode, "community"):
			//
			// Missing this was a real gap - the shape reads as an ordinary call
			// in expression position, so nothing else marked it.
			for _, e := range x.List {
				mark(e)
			}
		}
		return true
	})
}

// visit is the single walk step. It both LEARNS (which expressions are mode
// values) and JUDGES (which comparisons are readings).
func (a *analyser) visit(n ast.Node) bool {
	switch node := n.(type) {
	case *ast.AssignStmt:
		for i, lhs := range node.Lhs {
			if i >= len(node.Rhs) {
				// `a, b := f()` - one call feeding several names. If the call
				// is a mode value, every name it fills is treated as one.
				if len(node.Rhs) == 1 && a.isModeValue(node.Rhs[0]) {
					if id, ok := lhs.(*ast.Ident); ok {
						a.local[id.Name] = true
					}
				}
				continue
			}
			if a.isModeValue(node.Rhs[i]) {
				if id, ok := lhs.(*ast.Ident); ok {
					a.local[id.Name] = true
				}
			}
			if a.isModeNameKeyedMap(node.Rhs[i]) {
				if id, ok := lhs.(*ast.Ident); ok {
					a.nameMaps[id.Name] = true
				}
			}
			if a.isModeNameList(node.Rhs[i]) {
				if id, ok := lhs.(*ast.Ident); ok {
					a.nameLists[id.Name] = true
				}
			}
		}

	case *ast.RangeStmt:
		// `for _, m := range []string{"community", "evaluation"}` - the loop
		// variable now holds a MODE NAME, and `mode == m` below is a taxonomy
		// restated without a literal anywhere near the comparison.
		if a.isModeNameList(node.X) || a.isModeNameListIdent(node.X) {
			if id, ok := node.Value.(*ast.Ident); ok {
				a.nameLocal[id.Name] = true
			}
		}

	case *ast.IndexExpr:
		// `map[string]bool{"community": true, "": true}[mode]` - a whole
		// taxonomy as a map, indexed by the mode. The literal keys never appear
		// in a comparison, so no BinaryExpr shape can see it.
		if a.isModeValue(node.Index) && a.isModeNameKeyedMap(node.X) {
			a.record(node.Pos(), "map-index", "a map keyed by mode names")
		}

	case *ast.ValueSpec:
		for i, id := range node.Names {
			if i >= len(node.Values) {
				continue
			}
			if a.isModeValue(node.Values[i]) {
				a.local[id.Name] = true
			}
			// `var allowed = map[string]bool{...}` as well as `allowed := ...`.
			// The := form was handled and this one was not, which is the same
			// omission PASS A exists to correct for `local` - a var may be
			// spelled either way and neither spelling is rarer.
			if a.isModeNameKeyedMap(node.Values[i]) {
				a.nameMaps[id.Name] = true
			}
			if a.isModeNameList(node.Values[i]) {
				a.nameLists[id.Name] = true
			}
		}

	case *ast.BinaryExpr:
		if node.Op != token.EQL && node.Op != token.NEQ {
			return true
		}
		if lit, ok := a.modeNameOf(node.Y, true); ok && a.isModeValue(node.X) {
			a.record(node.Pos(), node.Op.String(), lit)
		} else if lit, ok := a.modeNameOf(node.X, true); ok && a.isModeValue(node.Y) {
			a.record(node.Pos(), node.Op.String(), lit)
		} else if a.isModeValue(node.X) && a.isModeNameIdent(node.Y) ||
			a.isModeValue(node.Y) && a.isModeNameIdent(node.X) {
			a.record(node.Pos(), node.Op.String(), "a mode name from a literal list")
		}

	case *ast.SwitchStmt:
		if node.Tag == nil || !a.isModeValue(node.Tag) {
			return true
		}
		var hits []string
		for _, stmt := range node.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			for _, e := range cc.List {
				if lit, ok := a.modeNameOf(e, true); ok {
					hits = append(hits, lit)
				}
			}
		}
		if len(hits) > 0 {
			// Sorted, so the reported detail does not depend on case order.
			sort.Strings(hits)
			a.record(node.Pos(), "switch", strings.Join(hits, ","))
		}

	case *ast.CallExpr:
		// A call is a seed, a taint carrier, and possibly a comparison.
		if a.isSeedCall(node) {
			a.seeds++
		}
		var modeArgs []int
		var litArgs []string
		for i, arg := range node.Args {
			if a.isModeValue(arg) {
				modeArgs = append(modeArgs, i)
			}
			if lit, ok := a.modeNameOf(arg, false); ok {
				litArgs = append(litArgs, lit)
			}
		}
		if len(modeArgs) > 0 && !a.isDeploymodeCall(node) {
			for _, i := range modeArgs {
				if keys, ok := a.callTaintKeys(node, i); ok {
					for _, key := range keys {
						a.newTaint[key] = true
					}
				}
			}
		}
		// strings.EqualFold(mode, "community") and friends: a comparison
		// spelled as a call.
		//
		// THE CONDITION IS THE RESULT'S POSITION, NOT THE CALLEE'S NAME. A list
		// of comparison functions would have to be extended for every new way
		// of spelling one, which is the enumeration this whole census exists to
		// replace. What separates
		//
		//	if strings.EqualFold(mode, "community") { ... }
		//
		// from
		//
		//	log.Printf("mode=%q category=%s", deploymode.Current(), CategoryEnterprise)
		//
		// is that the first RESULT decides something. The second put two
		// correct call sites in the first report. Excluded also when the callee
		// is this package, whose whole job is to take a mode value and a name.
		if a.boolCalls[node] && len(modeArgs) > 0 && len(litArgs) > 0 && !a.isDeploymodeCall(node) {
			sort.Strings(litArgs)
			a.record(node.Pos(), "call", strings.Join(litArgs, ","))
		}
	}
	return true
}

func (a *analyser) record(pos token.Pos, shape, detail string) {
	if !a.collect {
		return
	}
	a.readings = append(a.readings, reading{
		File:   a.rel,
		Func:   a.curFunc,
		Line:   a.fset.Position(pos).Line,
		Shape:  shape,
		Detail: strconv.Quote(detail),
	})
}

// isModeValue reports whether e carries a DEPLOYMENT_MODE value.
func (a *analyser) isModeValue(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return a.local[x.Name]
	case *ast.ParenExpr:
		return a.isModeValue(x.X)
	case *ast.CallExpr:
		if a.isSeedCall(x) {
			return true
		}
		// strings.ToLower(strings.TrimSpace(mode)) is still the mode.
		// platform/agent/dev_token_handler.go is written exactly that way, and
		// a census that stopped at the env read would not see it.
		//
		// deploymode's own calls are excluded: AppliesEnterpriseSchema() is a
		// bool, and treating this package's answers as mode values would make
		// every correct call site look like a violation.
		if a.isDeploymodeCall(x) {
			return false
		}
		for _, arg := range x.Args {
			if a.isModeValue(arg) {
				return true
			}
		}
	}
	return false
}

// isSeedCall reports whether the call IS the read of DEPLOYMENT_MODE: either
// os.Getenv/os.LookupEnv of the variable, or deploymode.Current().
func (a *analyser) isSeedCall(x *ast.CallExpr) bool {
	sel, ok := x.Fun.(*ast.SelectorExpr)
	if !ok {
		// Unqualified Current() - only meaningful inside this package, which
		// is exempt anyway, but recognising it keeps the seed count honest.
		if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "Current" && a.inDeploymode {
			return true
		}
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	if a.modePkgs[pkg.Name] && sel.Sel.Name == "Current" {
		return true
	}
	if pkg.Name == "os" && (sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv") {
		if len(x.Args) != 1 {
			return false
		}
		if s, ok := stringLit(x.Args[0]); ok {
			return s == EnvDeploymentMode
		}
		// os.Getenv(deploymode.EnvDeploymentMode) and the local-const form.
		switch arg := x.Args[0].(type) {
		case *ast.Ident:
			return a.consts[arg.Name] == EnvDeploymentMode
		case *ast.SelectorExpr:
			return a.consts[arg.Sel.Name] == EnvDeploymentMode
		}
	}
	return false
}

// isDeploymodeCall reports whether the callee is a function of THIS package.
func (a *analyser) isDeploymodeCall(x *ast.CallExpr) bool {
	sel, ok := x.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && a.modePkgs[pkg.Name]
}

// modeNameOf reports the mode name e denotes, whether written as a literal or
// as a constant identifier. admitUnset governs the empty string - see
// unsetLiteral.
func (a *analyser) modeNameOf(e ast.Expr, admitUnset bool) (string, bool) {
	ok := func(v string) bool {
		if v == unsetLiteral {
			return admitUnset
		}
		return a.names[v] || a.isModeFamilyPrefix(v)
	}
	if s, isLit := stringLit(e); isLit && ok(s) {
		return s, true
	}
	switch x := e.(type) {
	case *ast.Ident:
		if v, found := a.consts[x.Name]; found && ok(v) {
			return v, true
		}
	case *ast.SelectorExpr:
		if v, found := a.consts[x.Sel.Name]; found && ok(v) {
			return v, true
		}
	case *ast.ParenExpr:
		return a.modeNameOf(x.X, admitUnset)
	}
	return "", false
}

// isModeFamilyPrefix reports whether v names a FAMILY of modes rather than one
// mode - a proper prefix shared by two or more recognised spellings.
//
// `strings.HasPrefix(deploymentMode, "in-vpc-")` is live in the tree today
// (ee/platform/customer-portal/api/provision_admin_password.go) and is a
// re-derivation of the taxonomy exactly as a whole-name comparison is: it
// partitions the mode namespace using knowledge of how the names are spelled.
// A whole-name matcher cannot see it, which is how R3 found it.
//
// Length 4 is the floor so a one- or two-character prefix - shared by almost
// every mode, and overwhelmingly likely to be an unrelated string - does not
// turn the census into noise. Two or more, so a prefix that identifies exactly
// one mode is left to the whole-name path.
func (a *analyser) isModeFamilyPrefix(v string) bool {
	if len(v) < 4 {
		return false
	}
	if a.names[v] {
		return false
	}
	hits := 0
	for name := range a.names {
		if name != v && strings.HasPrefix(name, v) {
			hits++
		}
	}
	return hits >= 2
}

// isModeNameIdent reports whether e is an identifier bound to a mode name by a
// range over a literal list.
func (a *analyser) isModeNameIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && a.nameLocal[id.Name]
}

// isModeNameList reports whether e is a composite literal whose ELEMENTS are
// mode names - `[]string{"community", "evaluation"}`.
//
// Two or more, deliberately: a one-element list is the same thing as a literal
// comparison, which the BinaryExpr shape already reports, and requiring two
// keeps an unrelated single-element slice out of the report.
func (a *analyser) isModeNameList(e ast.Expr) bool {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return false
	}
	hits := 0
	for _, elt := range lit.Elts {
		if _, ok := a.modeNameOf(elt, true); ok {
			hits++
		}
	}
	return hits >= 2
}

// isModeNameListIdent reports whether e is an identifier assigned from a slice
// literal of mode names.
func (a *analyser) isModeNameListIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && a.nameLists[id.Name]
}

// isModeNameKeyedMap reports whether e is - or is an identifier assigned from -
// a composite literal whose KEYS are mode names.
func (a *analyser) isModeNameKeyedMap(e ast.Expr) bool {
	if id, ok := e.(*ast.Ident); ok {
		return a.nameMaps[id.Name]
	}
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return false
	}
	hits := 0
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if _, ok := a.modeNameOf(kv.Key, true); ok {
			hits++
		}
	}
	return hits >= 2
}

// stringLit unquotes a string literal expression.
func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}
