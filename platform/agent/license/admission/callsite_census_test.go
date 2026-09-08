// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestEveryPrincipalCreationPathReachesAdmitAndNothingElseCallsIt is the
// call-site census (#3593): "the code that runs is plural", so a limit
// enforced in one handler is not a platform property. This walks the AST of
// the two binaries that create principals and pins, by function name:
//
//  1. Admit is called from EXACTLY the permitted functions - one per binary -
//     and from nowhere else (a second call site is a second policy);
//  2. every creation path calls its binary's permitted function, so a path
//     that stops admitting fails the build;
//  3. sharedidentity.ResolveToken, the shared per-user token choke point, is
//     called only from resolveTokenAdmitted in the agent, so a plane cannot
//     resolve a human identity without admitting it.
//
// The creation paths are the ones the census on #3593 found live in the
// shipped binaries, keyed by the function that OWNS each boundary rather than
// by the handlers behind it: Authenticate is the one function every
// client-credential path traverses (17 handler call sites), and the two
// human-principal entries are the single production callers of their
// validator families, each already pinned by its own single-caller census.
//
// POSITIVE CONTROL (run, not reasoned): delete the admitPrincipal call from
// Authenticate and this test names Authenticate; add `tierAdmitter.Load().Admit(...)`
// to any handler and it names the handler. Both were run while the test was
// written; see the PR body.
func TestEveryPrincipalCreationPathReachesAdmitAndNothingElseCallsIt(t *testing.T) {
	root := repoRoot(t)

	type binary struct {
		dir       string
		permitted string            // the one function that may call Admit
		creators  []string          // functions that must call `permitted`
		chain     map[string]string // caller -> callee it must reach, for a path split across functions
	}
	binaries := []binary{
		{
			dir:       filepath.Join(root, "platform", "agent"),
			permitted: "admitPrincipal",
			creators: []string{
				"Authenticate",             // service_principal: every client-credential path
				"adaptedValidateUserToken", // human_principal: the HS256 per-user token entry
				"resolveTokenAdmitted",     // human_principal: the shared validator suite entry
				"admitNodeAndHeartbeat",    // node: the boot admission and its retry loop
				"runNodeHeartbeat",         // node: every renewal after that
			},
			// The node path is a CHAIN, because the admission runs in its own
			// goroutine so it cannot block boot (R3 round 1, H2). run.go calls
			// admitNodeAtBoot; that must reach the function which admits, or
			// the dimension is silently unenforced while every other check
			// still passes. Asserted here rather than assumed.
			chain: map[string]string{"admitNodeAtBoot": "admitNodeAndHeartbeat"},
		},
		{
			dir:       filepath.Join(root, "platform", "orchestrator"),
			permitted: "admitOrgRootPolicy",
			creators: []string{
				"(*PolicyService).validateTierForCreate", // org_root_policy: create
				"(*PolicyService).ImportPolicies",        // org_root_policy: bulk import
			},
		},
	}

	for _, b := range binaries {
		t.Run(filepath.Base(b.dir), func(t *testing.T) {
			admitCallers, callsOf := scanPackage(t, b.dir)

			// 1. Admit is called only from the permitted function.
			var others []string
			for fn := range admitCallers {
				if fn != b.permitted {
					others = append(others, fn)
				}
			}
			sort.Strings(others)
			if len(others) > 0 {
				t.Errorf("Admit is called from %v; the only permitted call site in this binary is %s", others, b.permitted)
			}
			if _, ok := admitCallers[b.permitted]; !ok {
				t.Fatalf("%s does not call Admit at all; the census has no subject", b.permitted)
			}

			// 2a. Every declared chain link holds.
			for caller, callee := range b.chain {
				calls, exists := callsOf[caller]
				if !exists {
					t.Errorf("chain entry %s no longer exists in %s", caller, b.dir)
					continue
				}
				if !calls[callee] {
					t.Errorf("%s no longer calls %s, so the path it fronts never reaches %s", caller, callee, b.permitted)
				}
			}

			// 2. Every creation path calls the permitted function.
			for _, creator := range b.creators {
				calls, exists := callsOf[creator]
				if !exists {
					t.Errorf("creation path %s no longer exists in %s; the census must be re-derived, not shortened", creator, b.dir)
					continue
				}
				if !calls[b.permitted] {
					t.Errorf("creation path %s does not call %s: a principal created there is never admitted", creator, b.permitted)
				}
			}
		})
	}

	// 2b. THE ENTERPRISE OVERLAY IS WHAT SHIPS, so it is scanned too.
	//
	// platform/agent/Dockerfile copies ee/platform/agent/<pkg>/* OVER
	// platform/agent/<pkg>/* for EDITION=enterprise, so a principal-creation
	// path added only in ee/, or an ee copy of an overlaid file that drops its
	// admitPrincipal call, would be invisible to a census that reads platform/
	// alone - and invisible in exactly the binary a paying customer runs.
	// (Enterprise-TAGGED files inside platform/agent are already covered:
	// go/parser ignores build constraints.) R3 round 1, M9.
	//
	// The rule for ee/ is the same one: nothing there may call Admit except
	// through admitPrincipal, which lives in platform/agent and survives the
	// overlay.
	eeAgent := filepath.Join(root, "ee", "platform", "agent")
	if _, err := os.Stat(eeAgent); err == nil {
		for _, sub := range eeAgentPackages(t, eeAgent) {
			admitCallers, _ := scanPackage(t, sub)
			var offenders []string
			for fn := range admitCallers {
				if fn != "admitPrincipal" {
					offenders = append(offenders, fn)
				}
			}
			sort.Strings(offenders)
			if len(offenders) > 0 {
				t.Errorf("%s calls Admit from %v; the enterprise overlay is what the shipped image compiles, "+
					"and its only permitted route is admitPrincipal in platform/agent", sub, offenders)
			}
		}
	} else {
		// The community mirror has no ee/ at all, and that is not a failure -
		// but it must be REPORTED, so a tree that lost ee/ for some other
		// reason does not read as a clean sweep.
		t.Logf("no ee/platform/agent in this tree (the community mirror): the overlay half of this census did not run")
	}

	// 2c. THE SERVICE-PRINCIPAL BOUNDARY IS DERIVED, NOT LISTED.
	//
	// Rule 2 pins that the functions NAMED in `creators` reach admitPrincipal,
	// which catches a path that stops admitting. It cannot catch a path that
	// never appears in the list - and the independent R3 proved that by
	// planting a new credential boundary which minted an `&AuthResult{...}`
	// without traversing Authenticate: every census stayed green. A service
	// principal is exactly "a thing that produced an authenticated
	// AuthResult", so the construction of that value is the boundary, and it
	// is pinned here the way ResolveToken is pinned below.
	//
	// The permitted set is small on purpose: authenticateLegacy builds the
	// three credential outcomes and buildAuthResult builds the rest, and both
	// are reached only through Authenticate, which admits. Everything else in
	// the list re-wraps an AuthResult that Authenticate already produced, for
	// a handler that needs a *User - those are not new boundaries, and each is
	// named with the reason it is not.
	// Each entry is a name AND the reason it is not a new boundary. The three
	// handlers below re-wrap an identity that apiAuthMiddleware already
	// obtained from Authenticate (auth.go:609) and stamped on the request
	// context: they read it back with AuthKindFromContext and rebuild the
	// struct only because ResolveUser takes an *AuthResult. The credential was
	// admitted before the handler ran. Checked, not assumed - a handler that
	// derived its identity from anything but the stamped context would be a
	// boundary and belongs in `creators` instead.
	permittedAuthResultBuilders := map[string]string{
		"authenticateLegacy":   "the credential branches themselves; Authenticate wraps it and admits",
		"buildAuthResult":      "the shared constructor authenticateLegacy returns through",
		"handleDecide":         "re-wraps the context identity apiAuthMiddleware already authenticated, for ResolveUser",
		"handleOpenAICompat":   "same: AuthKindFromContext plus a Client, for ResolveUser",
		"handlePolicyPreCheck": "same: the gateway pre-check's ResolveUser call",
		// The three below are named by the SIGNATURE rule added in round 2.
		// It is exhaustive over the escape path, so it also catches functions
		// that PASS a result through without minting one - which is noisier
		// than the construction rule and is the price of not being evadable.
		// Each was read before being listed:
		"Authenticate": "the admitting boundary ITSELF: authenticator.go:186 calls " +
			"admitPrincipal(ServicePrincipal) on the result before returning it. If this name ever " +
			"leaves `creators`, that check has gone and the census above fails on it first.",
		"authenticateMCPSession": "returns the *AuthResult that Authenticate produced (mcp_server_handler.go:1316, " +
			"`auth = authResult`) and mints nothing: no composite literal, no new(), no var declaration of the " +
			"type anywhere in it. The credential was admitted inside Authenticate before this returns.",
		"authenticateMCPServerRequest": "a one-line wrapper that forwards authenticateMCPSession's return " +
			"(mcp_server_handler.go:1277); it does not touch the value.",
	}
	// Both the community tree and the enterprise overlay: an overlay file is
	// compiled INSTEAD of its platform twin on the enterprise image, so a
	// boundary added only there would never be read by a platform-only scan.
	builders := authResultProducers(t,
		filepath.Join(root, "platform", "agent"),
		filepath.Join(root, "ee", "platform", "agent"))
	var newBoundaries []string
	for fn := range builders {
		if _, ok := permittedAuthResultBuilders[fn]; !ok {
			newBoundaries = append(newBoundaries, fn)
		}
	}
	sort.Strings(newBoundaries)
	if len(newBoundaries) > 0 {
		t.Errorf("these functions RETURN or CONSTRUCT an AuthResult without being a permitted builder: %v.\n\n"+
			"An AuthResult IS a service principal of its organization, so producing one is a credential boundary and "+
			"it must reach admitPrincipal. Either route it through Authenticate, or add it to creators AND to "+
			"permittedAuthResultBuilders with the reason it is not a new boundary. (R3 round 1, MAJOR-1: a planted "+
			"partner-key path that minted its own AuthResult passed every census. R3 round 2, MAJOR-R2-1: four "+
			"non-literal spellings - var, new, a dereference copy and a type alias - passed the composite-literal "+
			"rule that replaced it, which is why this now reads signatures first.)", newBoundaries)
	}
	if len(builders) == 0 {
		t.Fatal("no AuthResult producer found in platform/agent at all; the census is reading nothing")
	}

	// 3. sharedidentity.ResolveToken has exactly one caller in the agent.
	_, callsOf := scanPackage(t, filepath.Join(root, "platform", "agent"))
	var resolvers []string
	for fn, calls := range callsOf {
		if calls["sharedidentity.ResolveToken"] {
			resolvers = append(resolvers, fn)
		}
	}
	sort.Strings(resolvers)
	if len(resolvers) != 1 || resolvers[0] != "resolveTokenAdmitted" {
		t.Errorf("sharedidentity.ResolveToken is called from %v; the only permitted caller is resolveTokenAdmitted", resolvers)
	}
}

// scanPackage parses every non-test Go file in dir and returns (a) the set of
// enclosing functions that call a method named Admit (any receiver: the
// package is imported under one name and the method name is what a second
// call site would have to reuse), and (b) for every function, the set of
// callee names it invokes - bare (`admitPrincipal`), receiver-qualified
// (`(*PolicyService).ImportBulk` as the ENCLOSING name) and package-qualified
// (`sharedidentity.ResolveToken`).
func scanPackage(t *testing.T, dir string) (admitCallers map[string]bool, callsOf map[string]map[string]bool) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	admitCallers = map[string]bool{}
	callsOf = map[string]map[string]bool{}
	fset := token.NewFileSet()
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		scanned++
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			enclosing := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				enclosing = "(" + typeString(fn.Recv.List[0].Type) + ")." + fn.Name.Name
			}
			if callsOf[enclosing] == nil {
				callsOf[enclosing] = map[string]bool{}
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch f := call.Fun.(type) {
				case *ast.Ident:
					callsOf[enclosing][f.Name] = true
				case *ast.SelectorExpr:
					if pkg, ok := f.X.(*ast.Ident); ok {
						callsOf[enclosing][pkg.Name+"."+f.Sel.Name] = true
					}
					if f.Sel.Name == "Admit" {
						admitCallers[enclosing] = true
					}
				}
				return true
			})
		}
	}
	if scanned == 0 {
		t.Fatalf("no non-test Go files under %s", dir)
	}
	return admitCallers, callsOf
}

func typeString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.StarExpr:
		return "*" + typeString(x.X)
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		return typeString(x.X)
	}
	return "?"
}

// repoRoot walks up from this package to the directory holding go.work or
// the top-level CHANGELOG.md.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "platform", "agent", "license", "admission")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("repository root not found above the admission package")
	return ""
}

// eeAgentPackages lists the directories under ee/platform/agent that hold Go
// files, so the overlay scan covers each package the Dockerfile copies.
func eeAgentPackages(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() || strings.Contains(path, "/testdata") {
			return nil
		}
		entries, readErr := os.ReadDir(path)
		if readErr != nil {
			return readErr
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".go") {
				out = append(out, path)
				return nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(out) == 0 {
		t.Fatalf("ee/platform/agent exists but holds no Go package; the overlay scan would be vacuous")
	}
	return out
}

// authResultBuilders returns the enclosing function of every `&AuthResult{...}`
// composite literal in the package, which is the set of credential boundaries.
// authResultProducers returns the enclosing functions that can hand an
// AuthResult to a caller, in `dir` and in any overlay directory given.
//
// WHY TWO RULES, AND WHAT EACH IS FOR. Round 1 of the independent R3 asked for
// a derivation and got a composite-literal match: `&AuthResult{...}`. Round 2
// then evaded it four ways that are not exotic - `var ar AuthResult` with
// field assignment, `new(AuthResult)`, `cp := *existing`, and a type alias -
// all of which mint a credential and none of which is a composite literal.
//
//  1. SIGNATURE (exhaustive over the path that matters). Any function whose
//     RESULTS include AuthResult, *AuthResult, or a package-local alias of
//     either. This does not care how the value was built, so all four round-2
//     spellings are caught by it: a value that a caller receives had to come
//     back through a signature. This is the rule to trust.
//  2. CONSTRUCTION (a second, independent net). Composite literal,
//     `new(AuthResult)`, and `var x AuthResult` declarations, in function
//     bodies AND at package scope. It catches a value built in a function that
//     does not return it, which rule 1 cannot see. The package-scope half was
//     added in round 3: the walk descended into FuncDecl bodies only, so
//     `var x = &AuthResult{}` at the top of a file was invisible to BOTH
//     rules - it is not inside any function, and it is not returned by one.
//     Because rule 2 reads the type of the composite literal rather than of
//     its elements, an elided element type (`[]*AuthResult{{...}}`,
//     `map[string]*AuthResult{k: {...}}`) is covered by the outer literal and
//     needs no special case; each was planted to confirm it.
//
// WHAT IS STILL NOT COVERED, MEASURED AND NAMED rather than implied. Both
// residual shapes need the value to be built by a dereference copy (so rule 2
// sees no construction) AND handed out under a type that does not mention
// AuthResult (so rule 1 sees no producer). Each was planted and each passed:
//
//	// S1: the result type is an interface, so the name never appears.
//	func f(e *AuthResult) interface{} { cp := *e; return &cp }
//
//	// S2: the result type is a struct that EMBEDS it.
//	type wrap struct{ *AuthResult }
//	func f(e *AuthResult) wrap { cp := *e; return wrap{&cp} }
//
// Closing either needs go/types over the package - the type of `cp` is not
// derivable from this file's syntax - and that needs a loader (x/tools/go/
// packages) this module does not depend on. Adding a dependency to a test was
// judged the larger cost; the trade is recorded here so the next person sees a
// decision rather than an oversight.
//
// THE SEVERITY OF THE RESIDUAL, because that is what the trade turns on and a
// future reader deciding whether to spend the dependency needs it: neither
// shape can create a principal from nothing. Both start from `*e`, so the
// caller must ALREADY hold an authenticated *AuthResult - one that reached
// Authenticate and was admitted there. What they do is LAUNDER an existing
// admitted principal past this census, not mint a new one. That is a real gap
// and a materially smaller one than the shapes above, every one of which could
// forge a credential outright. If that ever stops being true - if a shape
// appears that produces an AuthResult without one to copy from and still
// evades both rules - the trade flips and the dependency is worth it.
//
// Five OTHER container shapes did evade an earlier version of rule 1 and are
// now closed by isAuthResult recursing into composite types: `<-chan *T`,
// `[]*T`, `map[string]*T`, `func() *T` and `...*T`. A function that only takes
// `...*AuthResult` as a PARAMETER is correctly not a producer - it consumes.
func authResultProducers(t *testing.T, dirs ...string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	// Names that mean AuthResult in this package: the type itself plus any
	// alias declared for it, so `type partnerAuth = AuthResult` cannot launder
	// the name past both rules.
	names := map[string]bool{"AuthResult": true}
	type parsed struct {
		file *ast.File
		path string
	}
	var files []parsed
	fset := token.NewFileSet()
	read := 0
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if os.IsNotExist(err) {
			// The community mirror has no ee/ at all, by construction. A
			// missing overlay is not a failure here; a missing EVERYTHING is,
			// and the caller's len(builders) == 0 check is what catches that.
			// (Found by running this census against the mirror simulation:
			// adding the overlay directory without this made the census fatal
			// on the community tree, where the file it protects still ships.)
			t.Logf("no %s in this tree (the community mirror): the overlay half of the producer census did not run", dir)
			continue
		}
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		read++
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			files = append(files, parsed{file: f, path: name})
		}
	}
	if read == 0 {
		t.Fatalf("none of %v exists, so this census read no source at all", dirs)
	}
	// Alias pass first, so the two rules below see the full name set. Repeated
	// to a fixed point so an alias of an alias resolves.
	for changed := true; changed; {
		changed = false
		for _, pf := range files {
			for _, decl := range pf.file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.TYPE {
					continue
				}
				for _, sp := range gd.Specs {
					ts, ok := sp.(*ast.TypeSpec)
					if !ok || !ts.Assign.IsValid() {
						continue // a defined type is a DIFFERENT type; only aliases launder the name
					}
					if id, ok := ts.Type.(*ast.Ident); ok && names[id.Name] && !names[ts.Name.Name] {
						names[ts.Name.Name] = true
						changed = true
					}
				}
			}
		}
	}
	// isAuthResult reports whether an expression names AuthResult or a
	// pointer to it, under any of the names resolved above.
	// It recurses through the COMPOSITE type expressions too, because a
	// signature rule that only understands `T` and `*T` is evaded by any
	// container: `<-chan *AuthResult`, `[]*AuthResult`,
	// `map[string]*AuthResult`, `func() *AuthResult` and `...*AuthResult` are
	// all a value reaching a caller, and all read as "not AuthResult" to a
	// two-case match. Measured: each of those five passed before this.
	var isAuthResult func(ast.Expr) bool
	isAuthResult = func(e ast.Expr) bool {
		switch x := e.(type) {
		case *ast.Ident:
			return names[x.Name]
		case *ast.StarExpr:
			return isAuthResult(x.X)
		case *ast.SelectorExpr:
			// agent.AuthResult, from an overlay file in another package.
			return names[x.Sel.Name]
		case *ast.ChanType:
			return isAuthResult(x.Value)
		case *ast.ArrayType:
			return isAuthResult(x.Elt)
		case *ast.MapType:
			// Either half carries it out.
			return isAuthResult(x.Key) || isAuthResult(x.Value)
		case *ast.Ellipsis:
			return isAuthResult(x.Elt)
		case *ast.ParenExpr:
			return isAuthResult(x.X)
		case *ast.FuncType:
			// A closure that returns one is a producer of one.
			if x.Results != nil {
				for _, r := range x.Results.List {
					if isAuthResult(r.Type) {
						return true
					}
				}
			}
			return false
		}
		return false
	}
	// constructedIn records a construction found anywhere in a node, under the
	// name given. Shared by the function walk and the package-level walk so
	// the two rules cannot drift apart.
	constructedIn := func(n ast.Node, name string) {
		ast.Inspect(n, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CompositeLit:
				if isAuthResult(x.Type) {
					out[name] = true
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 && isAuthResult(x.Args[0]) {
					out[name] = true
				}
			case *ast.ValueSpec:
				if x.Type != nil && isAuthResult(x.Type) {
					out[name] = true
				}
			}
			return true
		})
	}
	for _, pf := range files {
		// PACKAGE-LEVEL declarations, which the function walk below cannot
		// see: it descends into FuncDecl bodies only, so `var x = &AuthResult{}`
		// at package scope was invisible to both rules. Found by planting it
		// while checking a narrower finding; a package-level credential is a
		// credential.
		for _, decl := range pf.file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, sp := range gd.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, nm := range vs.Names {
					constructedIn(vs, "var "+nm.Name)
				}
			}
		}
		for _, decl := range pf.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			enclosing := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				enclosing = "(" + typeString(fn.Recv.List[0].Type) + ")." + fn.Name.Name
			}
			// Rule 1: the signature.
			if fn.Type.Results != nil {
				for _, r := range fn.Type.Results.List {
					if isAuthResult(r.Type) {
						out[enclosing] = true
					}
				}
			}
			// Rule 2: construction.
			constructedIn(fn.Body, enclosing)
		}
	}
	return out
}
