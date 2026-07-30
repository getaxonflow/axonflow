// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Repo-wide conformance guards for #3104.
//
// The policy matrix in egress_test.go proves the POLICIES agree. It cannot
// prove that a surface consults them: someone can always add a tenth
// classifier. These two tests close that, over the WHOLE tree rather than a
// diff — the failure mode of #3095 and #3104 was a copy nobody was looking at.
//
// Both fail closed. If the repo root cannot be located the test fails rather
// than silently scanning nothing, because a guard that skips when it cannot
// run is not a guard.

package egress

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// repoRoot walks up from the test's working directory looking for `platform/`.
//
// It anchors on `platform/` ONLY, never on `ee/`. `ee/` is stripped by the
// community sync filter (`.github/workflows/sync-community-repo.yml`
// `--exclude='ee/'`), and this package ships to the community mirror — an
// anchor that required `ee/go.mod` would hard-fail community CI on every run.
// Same contract and same reason as `lintRepoRoot` in
// platform/shared/tenantscope/tenantscope_lint_test.go.
//
// Fails the test if it runs out of parents: a guard that skips when it cannot
// run is not a guard.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot determine working directory: %v", err)
	}
	for {
		if st, statErr := os.Stat(filepath.Join(dir, "platform", "go.mod")); statErr == nil && !st.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate the repository root above %q (looked for platform/go.mod). "+
				"This guard must not be skipped — if the layout changed, fix the search, do not delete the test.", dir)
		}
		dir = parent
	}
}

// reservedRangeLiterals are the CIDR strings that only appear in an egress
// classifier. Matched against parsed STRING LITERALS, not raw file text, so a
// comment or a documentation block listing them (as the PII detectors in
// platform/shared/policy and platform/orchestrator do) is not a false positive.
var reservedRangeLiterals = map[string]bool{
	"10.0.0.0/8": true, "172.16.0.0/12": true, "192.168.0.0/16": true,
	"127.0.0.0/8": true, "169.254.0.0/16": true, "0.0.0.0/8": true,
	"0.0.0.0/32": true, "100.64.0.0/10": true, "198.18.0.0/15": true,
	"224.0.0.0/4": true, "224.0.0.0/24": true, "240.0.0.0/4": true,
	"192.0.0.0/24": true, "192.0.2.0/24": true, "198.51.100.0/24": true,
	"203.0.113.0/24": true, "255.255.255.255/32": true,
	"fc00::/7": true, "fe80::/10": true, "::1/128": true, "::/128": true,
	"ff02::/16": true, "ff00::/8": true, "2001:db8::/32": true,
	"64:ff9b::/96": true, "2002::/16": true, "::/96": true,
	"::ffff:0:0:0/96": true,
}

// reservedLiteralThreshold is 2, not 3. A classifier does not need a long
// table to be dangerous — the two most common ranges alone (`127.0.0.0/8` +
// `169.254.0.0/16`) are enough to look like a guard while permitting
// everything else. Two CIDR literals from this set in one non-test file is
// already a table.
const reservedLiteralThreshold = 2

// classifierName matches the names the nine pre-#3104 classifiers used, and
// then some. The prefix is deliberately not anchored to `is`/`check`: a
// reimplementation named `hostIsInternal` or `resolveIsBlocked` is the same
// defect wearing a different name.
var classifierName = regexp.MustCompile(`(?i)(private|reserved|internal|loopback|ssrf|blocked|egress|dialable|dialable)`)

// WHAT THIS LINT DOES NOT CATCH — read this before treating it as coverage.
//
// It is a keyword-and-shape heuristic, not a type-checked analysis, and a
// determined author can walk past it. Known gaps, established by adversarial
// review rather than guessed at:
//
//   - a classifier taking `netip.Addr` (which has its own IsPrivate/IsLoopback)
//     is caught only if its NAME matches; there is no type check for it;
//   - a function whose name shares no keyword with the list above
//     (`hostAllowed`, `canDial`, `vet`) is invisible;
//   - one CIDR literal plus octet arithmetic stays under the literal threshold;
//   - a type alias for net.IP, a generic parameter, or a method on a named IP
//     type defeats the parameter-shape check;
//   - it cannot tell whether a surface delegates to the RIGHT policy. A
//     callback surface that delegates to ConnectorEgress passes this lint —
//     that is pinned per surface instead, by a TestSurfaceUses*Egress in each
//     package.
//
// It is a speed bump against the accident that produced #3095 and #3104 —
// someone copying a predicate because it was easier than finding the shared
// one — not a proof that no tenth classifier can exist.

// walkGoFiles visits every non-test .go file under platform/ and ee/.
//
// A missing `ee/` is skipped with a log line, not an error: the community
// mirror does not carry it. `platform/` missing is still fatal, and the
// seen-count floor below still applies, so the guard cannot go vacuous.
func walkGoFiles(t *testing.T, root string, fn func(rel string, file *ast.File, fset *token.FileSet)) {
	t.Helper()
	seen := 0
	for _, sub := range []string{"platform", "ee"} {
		dir := filepath.Join(root, sub)
		if st, statErr := os.Stat(dir); os.IsNotExist(statErr) || (statErr == nil && !st.IsDir()) {
			if sub == "platform" {
				t.Fatalf("%s is missing; this guard cannot run", dir)
			}
			t.Logf("%s not present in this checkout (community sync strips ee/); skipping", dir)
			continue
		}
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				switch info.Name() {
				case "node_modules", "vendor", "testdata", ".git":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			// ParseComments is deliberately omitted: we look at literals only.
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				// An unparseable file must not silently reduce coverage.
				t.Errorf("cannot parse %s: %v", path, perr)
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			seen++
			fn(filepath.ToSlash(rel), f, fset)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", sub, err)
		}
	}
	if seen < 100 {
		t.Fatalf("only %d Go files scanned; the walk is not reaching the tree, so this guard is vacuous", seen)
	}
	t.Logf("scanned %d non-test Go files under platform/ and ee/", seen)
}

// TestNoLocalEgressClassifiers is the anti-drift guard. It fails if any file
// outside this package either (a) collects a table of reserved-range CIDR
// literals, or (b) declares a classifier-shaped function over net.IP whose
// body is more than a single delegation to this package.
//
// (b) matters as much as (a): a reimplementation using octet arithmetic —
// which is exactly how platform/connectors/base/security.go was written —
// contains no CIDR literals at all.
func TestNoLocalEgressClassifiers(t *testing.T) {
	root := repoRoot(t)
	const selfPkg = "platform/shared/egress/"

	walkGoFiles(t, root, func(rel string, f *ast.File, fset *token.FileSet) {
		if strings.HasPrefix(rel, selfPkg) {
			return
		}

		// (a) a table of reserved-range CIDR literals.
		var found []string
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if reservedRangeLiterals[v] {
				found = append(found, v)
			}
			return true
		})
		if len(found) >= reservedLiteralThreshold {
			t.Errorf("%s collects %d reserved-range CIDR literals (%s). The egress range table lives in "+
				"platform/shared/egress and nowhere else — #3104 found nine copies with five distinct behaviours. "+
				"Consume egress.ConnectorEgress or egress.CallbackEgress instead.", rel, len(found), strings.Join(found, ", "))
		}

		// (b) a classifier-shaped function that does more than delegate.
		//
		// Both a declared func AND a package-level var holding a func literal:
		// `var isPrivateIP = func(ip net.IP) bool { ... }` is the same defect,
		// and it is an idiom this repo already uses for test seams
		// (media/types.go validateURLForSSRF, webhooks/service.go
		// allowPrivateRanges), so it is the likeliest way the class comes back.
		for _, fn := range classifierShapedFuncs(f) {
			if !classifierName.MatchString(fn.name) || !takesIPArg(fn.typ) || isSingleDelegationToEgress(fn.body) {
				continue
			}
			t.Errorf("%s:%d declares %s, a classifier-shaped function over an IP address whose body is not a "+
				"single delegation to platform/shared/egress. Local egress predicates drift — that is the whole "+
				"finding of #3095 and #3104. Make it `return egress.<Policy>.Blocks(ip)`.",
				rel, fset.Position(fn.pos).Line, fn.name)
		}
	})
}

// classifierFunc is a function this lint can inspect regardless of how it was
// spelled: a top-level `func`, a method, or a package-level
// `var name = func(...)`. The last form is the likeliest way a local
// classifier comes back, because this repo already uses it for test seams.
type classifierFunc struct {
	name string
	typ  *ast.FuncType
	body *ast.BlockStmt
	pos  token.Pos
}

func classifierShapedFuncs(f *ast.File) []classifierFunc {
	var out []classifierFunc
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Body != nil {
				out = append(out, classifierFunc{d.Name.Name, d.Type, d.Body, d.Pos()})
			}
		case *ast.GenDecl:
			if d.Tok != token.VAR {
				continue
			}
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, val := range vs.Values {
					lit, ok := val.(*ast.FuncLit)
					if !ok || i >= len(vs.Names) {
						continue
					}
					out = append(out, classifierFunc{vs.Names[i].Name, lit.Type, lit.Body, lit.Pos()})
				}
			}
		}
	}
	return out
}

// takesIPArg reports whether any parameter is an IP address in a shape a
// classifier would take: net.IP or netip.Addr, through any combination of
// pointer, slice and variadic. `netip.Addr` is included because it carries its
// own IsPrivate/IsLoopback and is the modern way to write the same defect.
func takesIPArg(ft *ast.FuncType) bool {
	if ft == nil || ft.Params == nil {
		return false
	}
	var isIP func(ast.Expr) bool
	isIP = func(e ast.Expr) bool {
		switch t := e.(type) {
		case *ast.StarExpr:
			return isIP(t.X)
		case *ast.ArrayType:
			return isIP(t.Elt)
		case *ast.Ellipsis:
			return isIP(t.Elt)
		case *ast.SelectorExpr:
			pkg, ok := t.X.(*ast.Ident)
			if !ok {
				return false
			}
			return (pkg.Name == "net" && t.Sel.Name == "IP") ||
				(pkg.Name == "netip" && (t.Sel.Name == "Addr" || t.Sel.Name == "AddrPort"))
		}
		return false
	}
	for _, p := range ft.Params.List {
		if isIP(p.Type) {
			return true
		}
	}
	return false
}

// isSingleDelegationToEgress accepts EXACTLY one shape:
//
//	return egress.<Policy>.Blocks(<expr>)
//
// One return, one result, one call expression, selector rooted at the `egress`
// package identifier, method `Blocks`, and NO surrounding operators.
//
// The strictness is the point. An earlier revision accepted any single return
// that merely *mentioned* `egress`, which passed
//
//	return egress.CallbackEgress.Blocks(ip) && !ip.IsLoopback()
//
// — a function that reads as compliant while re-permitting loopback on a
// callback surface. `&&`-weakening a delegation is exactly how a "consume the
// shared policy" instruction gets subverted, so the delegation must be the
// whole expression, not a term in one.
//
// It also refuses a delegation through a local variable holding a Policy: the
// policy must be named at the call site, so `grep egress.CallbackEgress` finds
// every surface that uses it.
func isSingleDelegationToEgress(body *ast.BlockStmt) bool {
	if body == nil || len(body.List) != 1 {
		return false
	}
	ret, ok := body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return false
	}
	call, ok := ret.Results[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	method, ok := call.Fun.(*ast.SelectorExpr) // <policy>.Blocks
	if !ok || method.Sel.Name != "Blocks" {
		return false
	}
	policy, ok := method.X.(*ast.SelectorExpr) // egress.<Policy>
	if !ok {
		return false
	}
	pkg, ok := policy.X.(*ast.Ident)
	return ok && pkg.Name == "egress"
}

// TestLintCatchesKnownBypasses is the guard's own regression test.
//
// Every case below is a local egress classifier that an earlier revision of
// this lint WAVED THROUGH. A lint that fails open is worse than no lint,
// because it is read as coverage. Each case is parsed as real Go and run
// through the same two predicates TestNoLocalEgressClassifiers uses.
func TestLintCatchesKnownBypasses(t *testing.T) {
	bypasses := []struct{ name, src, why string }{
		{
			"and-weakened delegation",
			`package p
			import "net"
			import "axonflow/platform/shared/egress"
			func isPrivateIP(ip net.IP) bool { return egress.CallbackEgress.Blocks(ip) && !ip.IsLoopback() }`,
			"reads as compliant, re-permits loopback on a callback surface — the most dangerous shape",
		},
		{
			"negated delegation",
			`package p
			import "net"
			import "axonflow/platform/shared/egress"
			func isPrivateIP(ip net.IP) bool { return !egress.CallbackEgress.Blocks(ip) }`,
			"inverts the verdict entirely",
		},
		{
			"delegation to a non-Blocks method",
			`package p
			import "net"
			import "axonflow/platform/shared/egress"
			func isPrivateIP(ip net.IP) bool { _, ok := egress.Classify(ip); return ok }`,
			"Classify is fail-OPEN on malformed input; Blocks is not",
		},
		{
			"name not prefixed is/check",
			`package p
			import "net"
			func hostIsInternal(ip net.IP) bool { v := ip.To4(); return v != nil && v[0] == 10 }`,
			"octet arithmetic under a name the old regex did not match",
		},
		{
			"slice parameter",
			`package p
			import "net"
			func isPrivateAddrs(ips []net.IP) bool {
				for _, ip := range ips { if ip.IsLoopback() { return true } }
				return false
			}`,
			"[]net.IP is not *ast.SelectorExpr, so a shape check on the bare form misses it",
		},
		{
			"pointer parameter",
			`package p
			import "net"
			func isReservedIP(ip *net.IP) bool { return ip.IsLoopback() || ip.IsPrivate() }`,
			"same, through *net.IP",
		},
		{
			"func literal in a package-level var",
			`package p
			import "net"
			var isPrivateIP = func(ip net.IP) bool { return ip.IsLoopback() || ip.IsPrivate() }`,
			"the idiom this repo already uses for test seams (media validateURLForSSRF, webhooks allowPrivateRanges)",
		},
		{
			"func literal var that delegates then weakens",
			`package p
			import "net"
			import "axonflow/platform/shared/egress"
			var isPrivateIP = func(ip net.IP) bool { return egress.CallbackEgress.Blocks(ip) && !ip.IsLoopback() }`,
			"both evasions at once",
		},
		{
			"netip.Addr parameter",
			`package p
			import "net/netip"
			func isPrivateIP(a netip.Addr) bool { return a.IsLoopback() || a.IsPrivate() }`,
			"netip.Addr carries its own IsPrivate/IsLoopback — the modern way to write the same defect",
		},
		{
			"delegation through a local variable",
			`package p
			import "net"
			import "axonflow/platform/shared/egress"
			func isPrivateIP(ip net.IP) bool { pol := egress.ConnectorEgress; return pol.Blocks(ip) }`,
			"the policy must be named at the call site so grep finds every surface using it",
		},
		{
			"two-literal table",
			`package p
			var decoyRanges = []string{"169.254.0.0/16", "127.0.0.0/8"}`,
			"two ranges are enough to look like a guard while permitting everything else",
		},
	}

	for _, b := range bypasses {
		t.Run(b.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "decoy.go", b.src, 0)
			if err != nil {
				t.Fatalf("decoy does not parse: %v", err)
			}
			if !lintFlags(f) {
				t.Errorf("the lint does NOT flag this bypass — %s\n%s", b.why, b.src)
			}
		})
	}

	// Vacuity control: the one shape that MUST pass, or every surface in this
	// PR would be flagged and the lint would be useless.
	t.Run("the compliant shape passes", func(t *testing.T) {
		fset := token.NewFileSet()
		f, _ := parser.ParseFile(fset, "ok.go", `package p
		import "net"
		import "axonflow/platform/shared/egress"
		func isPrivateIP(ip net.IP) bool { return egress.CallbackEgress.Blocks(ip) }
		func isPrivateOrLoopback(ip net.IP) bool { return egress.ConnectorEgress.Blocks(ip) }`, 0)
		if lintFlags(f) {
			t.Error("the lint flags a correct single delegation; every surface in #3104 would fail")
		}
	})
}

// lintFlags applies both predicates of TestNoLocalEgressClassifiers to one
// parsed file and reports whether it would be flagged. Kept separate so the
// self-test above and the tree walk cannot drift apart.
func lintFlags(f *ast.File) bool {
	n := 0
	ast.Inspect(f, func(node ast.Node) bool {
		lit, ok := node.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if v, err := strconv.Unquote(lit.Value); err == nil && reservedRangeLiterals[v] {
			n++
		}
		return true
	})
	if n >= reservedLiteralThreshold {
		return true
	}
	for _, fn := range classifierShapedFuncs(f) {
		if classifierName.MatchString(fn.name) && takesIPArg(fn.typ) && !isSingleDelegationToEgress(fn.body) {
			return true
		}
	}
	return false
}

// eeTwins are the EGRESS-BEARING files the enterprise Docker overlay copies
// OVER their platform counterparts. The overlay is directory-wide —
// platform/agent/Dockerfile:50-59 does `cp -r /src/ee/platform/agent/hitl/*`
// and `.../circuitbreaker/*`, so it also overlays handler.go, repository.go,
// service.go and others. Those are NOT guarded here and may legitimately
// differ; this list is scoped to the two files that carry an egress
// classifier. Do not read it as covering the overlay.
//
// The ee/ copy is what runs in the Enterprise image, so an egress fix applied
// to one side only means Community and Enterprise enforce different rules.
var eeTwins = [][2]string{
	{"platform/agent/hitl/webhook.go", "ee/platform/agent/hitl/webhook.go"},
	{"platform/agent/circuitbreaker/notification.go", "ee/platform/agent/circuitbreaker/notification.go"},
}

// TestEETwinsAreInLockstep asserts each twin pair is identical from the
// `package` clause onward. The headers differ deliberately (the platform copy
// carries //go:build enterprise; the ee copy carries the overlay note), so
// only the header is exempt — every line of code must match.
func TestEETwinsAreInLockstep(t *testing.T) {
	root := repoRoot(t)
	if _, err := os.Stat(filepath.Join(root, "ee")); os.IsNotExist(err) {
		t.Skip("ee/ not present in this checkout (community sync strips it); no twins to compare")
	}
	for _, pair := range eeTwins {
		t.Run(pair[1], func(t *testing.T) {
			platformPath := filepath.Join(root, pair[0])
			eePath := filepath.Join(root, pair[1])

			// The header is exempt from the body compare below, and //go:build
			// lives in it — so the exemption would otherwise hide the one line
			// that decides which copy compiles. Assert the expected tag state
			// explicitly (#3104 R3 F8).
			if got := buildConstraints(t, platformPath); len(got) != 1 || got[0] != "//go:build enterprise" {
				t.Errorf("%s has build constraints %v, want exactly [\"//go:build enterprise\"]; "+
					"without it the file compiles into Community builds", pair[0], got)
			}
			if got := buildConstraints(t, eePath); len(got) != 0 {
				t.Errorf("%s has build constraints %v, want none; the ee/ overlay tree is compiled "+
					"unconditionally once applied, so a tag here silently drops the file from the "+
					"Enterprise image", pair[1], got)
			}

			a := readBodyFromPackageClause(t, platformPath)
			b := readBodyFromPackageClause(t, eePath)
			if a == b {
				return
			}
			al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
			for i := 0; i < len(al) || i < len(bl); i++ {
				var x, y string
				if i < len(al) {
					x = al[i]
				}
				if i < len(bl) {
					y = bl[i]
				}
				if x != y {
					t.Fatalf("%s and %s diverge at body line %d:\n  %s\n  %s\n\n"+
						"The enterprise Docker overlay copies the ee/ file OVER the platform one, so a change to "+
						"one side alone makes Community and Enterprise enforce different egress rules.",
						pair[0], pair[1], i+1, x, y)
				}
			}
		})
	}
}

func readBodyFromPackageClause(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	s := string(b)
	i := strings.Index(s, "\npackage ")
	if i < 0 {
		t.Fatalf("%s has no package clause", path)
	}
	return s[i+1:]
}

// buildConstraints returns the actual //go:build DIRECTIVE lines above the
// package clause — the region readBodyFromPackageClause deliberately ignores.
//
// It matches whole lines, not a substring: the ee/ header PROSE says "…without
// the //go:build enterprise tag…", and a Contains check reported that comment
// as a real constraint. Go itself only honours a directive that is its own
// line, so that is what is compared.
func buildConstraints(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", path, err)
	}
	s := string(b)
	i := strings.Index(s, "\npackage ")
	if i < 0 {
		t.Fatalf("%s has no package clause", path)
	}
	var out []string
	for _, line := range strings.Split(s[:i+1], "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//go:build") {
			out = append(out, trimmed)
		}
	}
	return out
}
