// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package sdkcompat

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// #3712 is not "reduce duplication". It is: the SDK maps were duplicated on the
// two /health planes, four lines above a pair of maps that had ALREADY been
// consolidated for exactly that reason, and the guard standing over the SDK
// copies was the same kind of guard that plugincompat's own doc records as
// insufficient. Consolidating the two copies closes today's instance. This test
// closes the class, by refusing a THIRD copy.
//
// It is derived, not enumerated. It does not know that the copies were in
// platform/agent and platform/orchestrator, and it does not carry a list of
// files to check. It walks every Go file in the repository -- both modules, both
// build-tag arms -- and reports every SDK-version map literal that is not in
// this package. A fourth plane, a new binary, a helper under ee/ that
// "temporarily" hardcodes the floors: all of them are reported by construction.
//
// The build-tag half of that is a property of the WALK, not of any fixture. It
// holds because the walk lists files and parses them syntactically, so a
// `//go:build enterprise` file is read like any other -- and it would stop
// holding the moment someone made the walk build-aware, which is a plausible
// "improvement". TestTheWalkIsNotBuildTagAware is that assertion. It cannot be
// stated in a TestTheDetectorCanFire fixture: parser.ParseFile never evaluates
// a build constraint, so a tagged fixture there behaves identically to an
// untagged one and asserts nothing about the tag.
//
// The signature it matches is derived from the canonical data, not written down:
// a map composite literal carrying at least two entries whose key is in IDs()
// and whose value looks like a version. Both halves are required, because
// neither alone is the shape:
//
//   - keys alone are not enough. ee/platform/checkpoint-service/pkg/sdkversions
//     holds map[string]string{"go": "getaxonflow/axonflow-sdk-go", ...} -- the
//     same five keys, GitHub repositories rather than versions. That is not a
//     second copy of anything and must not be reported. (F2 below.)
//   - version-shaped values alone are not enough either: the repository is full
//     of maps of versions keyed by something other than an SDK.
//
// It scores the CONFORMING SUBSET rather than requiring every entry to conform.
// The first version disqualified a literal at its first non-conforming entry,
// and R3 broke it three ways in minutes: `"go": "v8.0.0"` among four bare
// versions hid all five; a complete five-SDK copy plus one `"note"` key hid
// itself; a `const` identifier as key or value was not resolved. All three are
// realistic - every SDK release tag is written `vX.Y.Z` - and all three are
// fixtures below (F1d, F1e, F1f, F1g).
//
// WHAT IT DOES NOT COVER, stated rather than left to be discovered. This is a
// scan of Go map literals, and a determined third copy can be written outside
// that shape. Measured, not guessed - each of these was probed and returns zero
// hits: a map built by assignment (`m["go"] = "8.0.0"`); a
// `[]struct{ID, Min string}` table; one field per SDK on a struct; a value
// assembled by concatenation; a value or key imported from another package; a
// `const` in a SIBLING FILE of the same package; a package-level `var` rather
// than a `const`; a function-local `const`. The guard does not claim to close
// the shape space - a list of forms to refuse cannot terminate. What it closes
// is the form the two real copies took and the forms a person writing a third
// one by copy-paste would reach for.
//
// In the other direction it is deliberately WIDER than the compat maps: a map
// of toolchain versions keyed by language (`{"go": "1.25.1", "python":
// "3.13.0"}`) matches the signature and would be reported. Nothing in the tree
// has that shape today, and the failure message tells the reader to say what
// the literal is and narrow the signature deliberately rather than to add an
// exemption - which is the right trade when the alternative is a detector that
// misses a real copy.
//
// It is also Go-only. `docs/api/agent-api.yaml` and
// `docs/api/orchestrator-api.yaml` restate the same ten values in their
// `SDKCompatInfo` `example:` blocks - those ARE guarded now, by
// openapi_examples_test.go beside this file, and both had drifted when it was
// written. `docs/COMPATIBILITY_MATRIX.md` restates them in prose and is NOT
// guarded by anything; it is accurate today and is recorded as a known third
// copy on the audit umbrella rather than papered over here.
//
// TestNoSecondCopyOfTheSDKCompatMaps is the guard. TestTheDetectorCanFire is its
// survivor: a detector that reports nothing because it recognises nothing is
// indistinguishable from a clean tree, so the detector is run against twelve
// fixtures - seven synthetic third copies that must be flagged, four decoys
// that must not be, and one borderline shape (F6) recorded as reported on
// purpose.

// versionShaped matches a value that looks like a released version: "8.0.0",
// "0.7.0", "1.2.3-rc1", and "v8.0.0". Deliberately not a strict semver: the
// point is to separate versions from repository names and free text, not to
// validate a release tag.
//
// The leading `v` is not decoration. Every SDK release tag is written `vX.Y.Z`,
// and this package's own doc explains that Go's major bump changes the import
// path to `axonflow-sdk-go/v8` - so `"go": "v8.0.0"` is a natural way to write
// a third copy, and without this it was invisible.
var versionShaped = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+`)

// minKeysToLookLikeACopy is 2 rather than len(IDs()): a partial copy is the
// interesting case. A third site that hardcodes the floor for two SDKs is
// exactly as capable of drifting as one that hardcodes all five, and is likelier
// to be written, because whoever writes it only needs the two.
const minKeysToLookLikeACopy = 2

type hit struct {
	file string
	line int
	keys []string
}

// findSDKVersionMaps parses one Go file and returns every map composite literal
// that carries the SDK-compat signature. Parse failures are returned, never
// swallowed: a file this walk cannot read is a file a third copy could hide in.
func findSDKVersionMaps(path string, fset *token.FileSet) ([]hit, error) {
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}
	known := make(map[string]bool, len(IDs()))
	for _, id := range IDs() {
		known[id] = true
	}

	// String constants declared in THIS FILE, so `const goFloor = "8.0.0"` used
	// as a key or a value is resolved rather than skipped.
	//
	// The boundary is the FILE, not the package, and saying so matters: a
	// `consts.go` beside a `compat.go` is idiomatic Go and is a hand-maintained
	// copy by every definition this guard uses, and it is NOT resolved here. So
	// is a package-level `var` (rather than `const`), and so is a
	// function-local one. Nor is lexical scope modelled: a local variable that
	// SHADOWS a file constant resolves to the constant, which is a wrong
	// resolution rather than a conservative one. These are listed in the
	// package-level note above with the rest of the uncovered shape space.
	consts := fileConsts(f)

	var hits []hit
	ast.Inspect(f, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || len(cl.Elts) < minKeysToLookLikeACopy {
			return true
		}
		// Count the entries that CONFORM, rather than requiring all of them to.
		// The first version disqualified a literal on its first non-conforming
		// entry, which meant the complete five-SDK copy plus one `"note":
		// "see the runbook"` key was invisible while a two-key partial was
		// caught - the exact inverse of the threshold's own justification.
		var keys []string
		for _, e := range cl.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			k, kOK := constString(kv.Key, consts)
			v, vOK := constString(kv.Value, consts)
			if kOK && vOK && known[k] && versionShaped.MatchString(v) {
				keys = append(keys, k)
			}
		}
		if len(keys) < minKeysToLookLikeACopy {
			return true
		}
		sort.Strings(keys)
		hits = append(hits, hit{file: path, line: fset.Position(cl.Lbrace).Line, keys: keys})
		return true
	})
	return hits, nil
}

// fileConsts collects `const name = "literal"` declarations so an identifier
// used as a key or a value can be resolved to the string it stands for.
func fileConsts(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
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
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if v, err := strconv.Unquote(lit.Value); err == nil {
					out[name.Name] = v
				}
			}
		}
	}
	return out
}

func constString(e ast.Expr, consts map[string]string) (string, bool) {
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
	case *ast.Ident:
		s, ok := consts[v.Name]
		return s, ok
	}
	return "", false
}

// repoRoot walks up from the package directory to the repository root.
// Structural, so it does not depend on a checkout path, a symlink, or where the
// binary was built.
//
// It anchors on platform/go.mod ALONE, and that is the whole point rather than
// a convenience. THIS PACKAGE IS RUN IN TWO DIFFERENT TREES. The community
// mirror simulation stages a copy through the sync workflow's rules and then
// replays `unit-tests-platform-packages` on it, and the sync excludes `ee/`
// wholesale - so in the tree this test is run in there, `ee/` DOES NOT EXIST.
// An earlier version required both module files and would have failed with
// "could not find a directory holding both", reddening the Community Mirror
// Simulation for a reason that has nothing to do with a second copy. Verified
// by running this package against a tree containing only platform/.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "platform", "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find a directory holding platform/go.mod above %s; "+
				"the walk would have covered nothing and this guard would pass vacuously", dir)
		}
		dir = parent
	}
}

func walkGoFiles(t *testing.T, root string, visit func(rel, abs string)) (files int) {
	t.Helper()
	skipDir := map[string]bool{
		".git": true, "node_modules": true, "vendor": true,
		"testdata": true, ".venv": true, "target": true,
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		files++
		visit(filepath.ToSlash(rel), path)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return files
}

func TestNoSecondCopyOfTheSDKCompatMaps(t *testing.T) {
	root := repoRoot(t)
	// The canonical home is derived from where this test itself lives, not
	// written as a string: move the package and the exemption moves with it.
	selfDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	canonicalRel, err := filepath.Rel(root, selfDir)
	if err != nil {
		t.Fatalf("locating this package under %s: %v", root, err)
	}
	canonicalRel = filepath.ToSlash(canonicalRel) + "/"

	// The trees a third copy would plausibly land in. `ee/` is required only
	// where it exists: this same package runs inside the staged community
	// mirror, from which the sync strips `ee/` wholesale. Requiring it
	// unconditionally would red the mirror; dropping it unconditionally would
	// silently stop claiming enterprise coverage in the tree that has it. So the
	// expectation is derived from the tree under test.
	mustReach := []string{"platform/agent/", "platform/orchestrator/"}
	if _, err := os.Stat(filepath.Join(root, "ee")); err == nil {
		mustReach = append(mustReach, "ee/")
	} else {
		t.Logf("no ee/ in %s - this is the community tree, so the enterprise-module leg of the "+
			"coverage floor is not applicable here; it is asserted in the enterprise tree", root)
	}

	fset := token.NewFileSet()
	var offenders, canonicalSource, canonicalTests []hit
	var parseErrs []string
	reached := map[string]bool{}
	files := walkGoFiles(t, root, func(rel, abs string) {
		for _, prefix := range mustReach {
			if strings.HasPrefix(rel, prefix) {
				reached[prefix] = true
			}
		}
		hits, err := findSDKVersionMaps(abs, fset)
		if err != nil {
			parseErrs = append(parseErrs, rel+": "+err.Error())
			return
		}
		for _, h := range hits {
			h.file = rel
			// The exemption is this package's own directory, not everything
			// beneath it: a future `platform/shared/sdkcompat/something` would
			// otherwise inherit the exemption without anyone deciding it should.
			inCanonical := strings.HasPrefix(rel, canonicalRel) &&
				!strings.Contains(strings.TrimPrefix(rel, canonicalRel), "/")
			switch {
			case !inCanonical:
				offenders = append(offenders, h)
			case strings.HasSuffix(rel, "_test.go"):
				// This package's own pin test restates the values on purpose:
				// that is what makes a bump a reviewed edit. It is beside the
				// map it pins, so it cannot be the thing that drifts.
				canonicalTests = append(canonicalTests, h)
			default:
				canonicalSource = append(canonicalSource, h)
			}
		}
	})

	// --- the floors, each falsifiable by an input ---------------------------
	//
	// A source-scanning guard reports nothing when it reads nothing, and
	// "nothing found" is the same output as "the tree is clean". These are the
	// four ways this walk could have been empty, each checked against something
	// the repository actually contains rather than against a number chosen to
	// pass.
	if files == 0 {
		t.Fatalf("the walk visited 0 Go files under %s; every assertion below would be vacuous", root)
	}
	for _, prefix := range mustReach {
		if !reached[prefix] {
			t.Fatalf("the walk never reached %s -- the two former copies lived in platform/agent and "+
				"platform/orchestrator, and a third would most plausibly land in one of %v; %d files were visited",
				prefix, mustReach, files)
		}
	}
	if len(parseErrs) > 0 {
		t.Errorf("%d Go file(s) could not be parsed, so they were not searched:\n  %s",
			len(parseErrs), strings.Join(parseErrs, "\n  "))
	}
	if len(canonicalSource) != 2 {
		// Errorf, not Fatalf: if this package grew a third legitimate map the
		// floor is wrong, but the offender list below is still the answer the
		// reader came for, and aborting here would replace it with a message
		// blaming the detector.
		t.Errorf("expected exactly 2 SDK-version map literals in the non-test sources of %s (minVersion and recommendedVersion), found %d: %v\n"+
			"if this is 0, the detector cannot recognise the very shape it is looking for and its silence about the rest of the tree means nothing",
			canonicalRel, len(canonicalSource), canonicalSource)
	}
	if len(canonicalTests) == 0 {
		// Errorf for the same reason as the floor above, which was changed and
		// this one was not: both sit BEFORE the offender report, so a Fatalf
		// here replaces the answer the reader came for with a message about the
		// detector. Two identical floors, one fixed - the class, not the
		// instance.
		t.Errorf("this package's own test files hold no SDK-version map literal; TestPinnedToReleaseTrain is what makes a bump "+
			"a reviewed edit, and the detector not seeing it means the walk is not reading %s the way it thinks it is", canonicalRel)
	}

	// --- the guard ----------------------------------------------------------
	if len(offenders) > 0 {
		var b strings.Builder
		for _, h := range offenders {
			b.WriteString("\n  " + h.file + ":" + strconv.Itoa(h.line) + "  keys=" + strings.Join(h.keys, ","))
		}
		t.Errorf("SDK-version map literal(s) outside %s:%s\n\n"+
			"This is #3712's defect class. The SDK floors were literals on BOTH /health planes, so the two "+
			"ports could answer the same question differently -- which is what the plugin maps four lines "+
			"below them had already been consolidated to stop. Read the values from this package "+
			"(sdkcompat.MinVersions() / sdkcompat.RecommendedVersions()) rather than restating them. If the "+
			"literal above is genuinely not a compat map, it matched because its keys are SDK ids and its "+
			"values are version-shaped; say what it is here and narrow the signature deliberately.",
			canonicalRel, b.String())
	}

	t.Logf("walked %d Go files under %s; %d canonical source literals, %d canonical pin literals, %d offenders",
		files, root, len(canonicalSource), len(canonicalTests), len(offenders))
}

// TestTheDetectorCanFire is the survivor for the guard above. A detector that
// recognises nothing reports a clean tree, and the two outputs are identical, so
// the guard's silence is only worth something if the detector is shown to fire
// on the shape it claims to match and to stay silent on the shapes it must not.
func TestTheDetectorCanFire(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		{
			name: "F1 a third copy: SDK ids mapped to versions",
			src: `package p
var floors = map[string]string{
	"python": "8.0.0",
	"go":     "8.0.0",
	"rust":   "0.7.0",
}`,
			want: 1,
		},
		{
			name: "F1b a partial third copy, two ids only",
			src: `package p
func f() map[string]string { return map[string]string{"java": "8.0.0", "typescript": "8.0.0"} }`,
			want: 1,
		},
		{
			name: "F1c a third copy nested inside a struct literal",
			src: `package p

type info struct{ Min map[string]string }

var x = info{Min: map[string]string{"python": "8.0.0", "go": "8.0.0"}}`,
			want: 1,
		},
		{
			name: "F1d Go-module-style versions, written with the leading v every release tag carries",
			src: `package p
var floors = map[string]string{"go": "v8.0.0", "python": "v8.0.0"}`,
			want: 1,
		},
		{
			name: "F1e the complete five-SDK copy with ONE extra non-SDK key",
			src: `package p
var floors = map[string]string{
	"python":     "8.0.0",
	"typescript": "8.0.0",
	"go":         "8.0.0",
	"java":       "8.0.0",
	"rust":       "0.7.0",
	"note":       "see the release runbook",
}`,
			want: 1,
		},
		{
			// Illustrative, not a pin: with EITHER the v-prefix or the
			// subset-scoring fix reverted it still reports 1, because the other
			// fix carries it. F1d and F1e are what hold those two lines
			// individually. Kept because it is a shape someone will write.
			name: "F1f one entry written with a v prefix among four bare versions",
			src: `package p
var floors = map[string]string{
	"python":     "8.0.0",
	"typescript": "8.0.0",
	"go":         "v8.0.0",
	"java":       "8.0.0",
}`,
			want: 1,
		},
		{
			name: "F1g file-local const identifiers as the key and as the value",
			src: `package p

const (
	goID    = "go"
	goFloor = "8.0.0"
	pyID    = "python"
)

var floors = map[string]string{goID: goFloor, pyID: "8.0.0"}`,
			want: 1,
		},
		{
			name: "F2 the checkpoint-service decoy: same keys, repository names",
			src: `package p
var repos = map[string]string{
	"python":     "getaxonflow/axonflow-sdk-python",
	"go":         "getaxonflow/axonflow-sdk-go",
	"typescript": "getaxonflow/axonflow-sdk-typescript",
}`,
			want: 0,
		},
		{
			name: "F3 versions keyed by something that is not an SDK",
			src: `package p
var plugins = map[string]string{"openclaw": "2.4.0", "cursor": "1.4.0"}`,
			want: 0,
		},
		{
			name: "F4 a single SDK id and version is below the copy threshold",
			src: `package p
var one = map[string]string{"go": "8.0.0"}`,
			want: 0,
		},
		{
			name: "F5 one conforming entry beside unrelated keys is still below the threshold",
			src: `package p
var mixed = map[string]string{"go": "8.0.0", "notes": "see the runbook", "owner": "platform"}`,
			want: 0,
		},
		{
			name: "F6 a version-shaped value that is not a version line: a date",
			src: `package p
var when = map[string]string{"go": "2026.09.04", "python": "2026.09.04"}`,
			// Reported on purpose. A date is version-shaped, so this matches -
			// and a date sitting under `"go":` / `"python":` keys is anomalous
			// enough that a human should look at it. Recorded here rather than
			// exempted, because narrowing the value shape to exclude dates
			// would also exclude a calendar-versioned SDK.
			want: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "probe.go")
			if err := os.WriteFile(path, []byte(tc.src), 0o600); err != nil {
				t.Fatalf("writing the fixture: %v", err)
			}
			hits, err := findSDKVersionMaps(path, token.NewFileSet())
			if err != nil {
				t.Fatalf("the fixture did not parse, so this case tested nothing: %v", err)
			}
			if len(hits) != tc.want {
				t.Errorf("detector reported %d hit(s), want %d: %v", len(hits), tc.want, hits)
			}
		})
	}
}

// TestTheWalkIsNotBuildTagAware pins that a file behind `//go:build enterprise`
// is searched. The two copies this guard replaced were untagged, but the
// enterprise tree is where a third one would most plausibly be written, and
// `go test` without `-tags enterprise` compiles none of it -- a build tag hides
// a file from a test runner more quietly than a module boundary does.
//
// The mutant it dies to is a walk that skips a file whose build constraints
// exclude the current build, which is exactly what switching this scan to
// go/packages or to `go list` would do for free.
func TestTheWalkIsNotBuildTagAware(t *testing.T) {
	dir := t.TempDir()
	const src = `//go:build enterprise

package p

var floors = map[string]string{"go": "8.0.0", "python": "8.0.0"}`
	path := filepath.Join(dir, "tagged.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}

	var seen int
	files := walkGoFiles(t, dir, func(rel, abs string) {
		seen++
		hits, err := findSDKVersionMaps(abs, token.NewFileSet())
		if err != nil {
			t.Fatalf("the tagged file did not parse, so this test asserted nothing: %v", err)
		}
		if len(hits) != 1 {
			t.Errorf("%s: a '//go:build enterprise' file yielded %d hit(s), want 1; the walk is skipping "+
				"files by build constraint, so every SDK map in the enterprise tree is invisible to it", rel, len(hits))
		}
	})
	if files != 1 || seen != 1 {
		t.Fatalf("the walk visited %d file(s) (callback ran %d times), want exactly 1; "+
			"a walk that visited nothing would have made the assertion above vacuous", files, seen)
	}
}
