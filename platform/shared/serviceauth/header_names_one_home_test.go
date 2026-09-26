// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package serviceauth

import (
	"fmt"
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

// The internal-service header names have ONE home: ServiceIDHeader and
// ServiceTokenHeader in serviceauth.go (#4249). That is a claim about every
// other file, so it is checked against every other file.
//
// The guard walks every non-test .go file under the repository's Go roots
// (headerNameRoots: platform/ and ee/, both modules, and examples/, scripts/,
// runtime-e2e/ and sdk/) and parses each one syntactically, so a
// `//go:build enterprise` file is read like any other. It reports every string
// literal that spells either name, or the "X-Internal-Service-" stem, in ANY
// case, except the two constant definitions. The case matters:
// http.Header.Set canonicalises its key, so "x-internal-service-id" at a
// writer reaches the wire as the same header and a second spelling is
// invisible at runtime. Only the source can show it.
//
// A floor per root (headerNameRootFloors) refuses a walk that lost a root, and
// both definitions must be found. A file that does not parse fails the walk.
//
// WHAT IT DOES NOT READ OR COVER, stated:
//   - directories named node_modules, vendor, testdata or .git (skipped by
//     name: dependencies, fixtures and git's store, none of them a writer);
//   - a symlinked directory: the walk does not follow links, because a
//     worktree can carry a symlink into the main clone and a walk that
//     followed it would read another tree. Each one is COUNTED and named in
//     the test log and in any failure, so a directory that went unread is
//     never silent;
//   - a name assembled from fragments that do not themselves contain the stem
//     or a whole name (for example "X-Internal-" + "Service-ID"), and a name
//     built at runtime;
//   - test files, which spell the names on purpose to assert the wire.

var headerNameSpellings = []string{
	strings.ToLower(ServiceIDHeader),
	strings.ToLower(ServiceTokenHeader),
	"x-internal-service-",
}

// headerNameHome is where the two constants are defined, relative to the repo root.
const headerNameHome = "platform/shared/serviceauth/serviceauth.go"

// headerNameRoots are the directories the guard walks, relative to the repo root.
var headerNameRoots = []string{"platform", "ee", "examples", "scripts", "runtime-e2e", "sdk"}

// headerNameRootFloors is the least number of non-test .go files the walk must
// read under each root, so losing any one root reds even though the total
// would still look large. Measured 2026-09-23: platform 921, ee 248, examples
// 79, runtime-e2e 5, scripts 1, sdk 1. The floors sit well under those.
var headerNameRootFloors = map[string]int{
	"platform": 600, "ee": 150, "examples": 40, "runtime-e2e": 3, "scripts": 1, "sdk": 1,
}

// headerNameEnterpriseOnlyRoots are the roots the community sync removes or
// empties of Go: ee/ and runtime-e2e/ are stripped whole, and scripts/ ships
// without its one .go file. The sync treats scripts/ as an allowlist - named
// lint scripts, scripts/local-dev/ and scripts/ci/go-mod-verify.sh are
// included, then `--exclude='/scripts/*'` drops everything else - and the .go
// file, scripts/key-rotation/main.go, is in none of the included paths.
// On a community-mirror checkout their floors cannot be met, so they are held
// to their floors on the enterprise tree only. platform/, examples/ and sdk/
// ship on both trees and keep their floors everywhere.
var headerNameEnterpriseOnlyRoots = map[string]bool{"ee": true, "runtime-e2e": true, "scripts": true}

// headerNameOnEnterpriseTree reports whether root is an enterprise checkout.
// ee/ is what the sync strips whole, so its presence is what tells the two
// trees apart; a mirror checkout is exactly a tree without it. Only an ABSENT
// ee/ reads as a mirror: any other outcome (a permission error, a broken
// link) is treated as the enterprise tree, so every floor stays in force and
// the walk reports the error rather than the guard quietly reading less.
// Lstat, not Stat: Stat follows a broken link to ENOENT and would call it a
// mirror.
func headerNameOnEnterpriseTree(root string) bool {
	_, err := os.Lstat(filepath.Join(root, "ee"))
	return !os.IsNotExist(err)
}

// TestTheMirrorDetectorFailsClosed pins that only an absent ee/ selects the
// mirror's weaker floors: a present ee/ and a broken ee link both keep the
// enterprise tree's.
func TestTheMirrorDetectorFailsClosed(t *testing.T) {
	absent := t.TempDir()
	if headerNameOnEnterpriseTree(absent) {
		t.Error("a tree with no ee/ was read as the enterprise tree")
	}
	present := t.TempDir()
	if err := os.Mkdir(filepath.Join(present, "ee"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !headerNameOnEnterpriseTree(present) {
		t.Error("a tree with ee/ was read as a mirror")
	}
	broken := t.TempDir()
	if err := os.Symlink(filepath.Join(broken, "gone"), filepath.Join(broken, "ee")); err != nil {
		t.Fatal(err)
	}
	if !headerNameOnEnterpriseTree(broken) {
		t.Error("a tree whose ee is a broken link was read as a mirror; it must keep the enterprise floors")
	}
}

// headerNameWalkRoots are the roots the guard walks on this tree: all of them
// on the enterprise tree, and on a mirror every root that exists, so a Go file
// that leaked into a stripped root would still be read.
func headerNameWalkRoots(root string) []string {
	if headerNameOnEnterpriseTree(root) {
		return headerNameRoots
	}
	var out []string
	for _, r := range headerNameRoots {
		if _, err := os.Stat(filepath.Join(root, r)); err == nil {
			out = append(out, r)
		}
	}
	return out
}

// headerNameFloorRoots are the roots held to their floors on this tree.
func headerNameFloorRoots(root string) []string {
	if headerNameOnEnterpriseTree(root) {
		return headerNameRoots
	}
	var out []string
	for _, r := range headerNameRoots {
		if !headerNameEnterpriseOnlyRoots[r] {
			out = append(out, r)
		}
	}
	return out
}

type headerNameSources struct {
	fset    *token.FileSet
	files   map[string]*ast.File // repo-relative, slash-separated
	perRoot map[string]int       // files read under each walked root
	// symlinkedDirs are the directories the walk did not enter because they
	// are symlinks, repo-relative.
	symlinkedDirs []string
}

// unread says which directories went unread, for a failure message.
func (s headerNameSources) unread() string {
	if len(s.symlinkedDirs) == 0 {
		return "the walk entered every directory it did not skip by name"
	}
	return fmt.Sprintf("the walk did not follow %d symlinked director(ies): %s", len(s.symlinkedDirs), strings.Join(s.symlinkedDirs, ", "))
}

func parseHeaderNameSources(t *testing.T, root string, dirs ...string) headerNameSources {
	t.Helper()
	src := headerNameSources{fset: token.NewFileSet(), files: map[string]*ast.File{}, perRoot: map[string]int{}}
	for _, dir := range dirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type()&os.ModeSymlink != 0 {
				if fi, statErr := os.Stat(path); statErr == nil && fi.IsDir() {
					rel, relErr := filepath.Rel(root, path)
					if relErr != nil {
						return relErr
					}
					src.symlinkedDirs = append(src.symlinkedDirs, filepath.ToSlash(rel))
				}
				return nil
			}
			if d.IsDir() {
				switch d.Name() {
				case "node_modules", "vendor", "testdata", ".git":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			f, err := parser.ParseFile(src.fset, path, nil, 0)
			if err != nil {
				return err
			}
			src.files[filepath.ToSlash(rel)] = f
			src.perRoot[dir]++
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return src
}

// headerNameViolations returns one line per literal that spells a header name
// outside its definition, and how many of the two definitions it found.
func headerNameViolations(src headerNameSources) (violations []string, definitions int) {
	rels := make([]string, 0, len(src.files))
	for rel := range src.files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		f := src.files[rel]
		// The definitions: the two named constants in the home file.
		defined := map[*ast.BasicLit]bool{}
		if rel == headerNameHome {
			ast.Inspect(f, func(n ast.Node) bool {
				vs, ok := n.(*ast.ValueSpec)
				if !ok {
					return true
				}
				for i, name := range vs.Names {
					if (name.Name == "ServiceIDHeader" || name.Name == "ServiceTokenHeader") && i < len(vs.Values) {
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok {
							defined[lit] = true
							definitions++
						}
					}
				}
				return true
			})
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING || defined[lit] {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil {
				value = lit.Value
			}
			lower := strings.ToLower(value)
			for _, spelling := range headerNameSpellings {
				if strings.Contains(lower, spelling) {
					violations = append(violations, rel+":"+strconv.Itoa(src.fset.Position(lit.Pos()).Line)+
						": "+lit.Value+" spells an internal-service header name; use serviceauth.ServiceIDHeader or serviceauth.ServiceTokenHeader")
					break
				}
			}
			return true
		})
	}
	return violations, definitions
}

func TestTheInternalServiceHeaderNamesAreSpelledOnlyInTheirHome(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	src := parseHeaderNameSources(t, root, headerNameWalkRoots(root)...)
	t.Log(src.unread())
	if !headerNameOnEnterpriseTree(root) {
		t.Logf("a community-mirror checkout: walked %v and held %v to their floors; ee/, runtime-e2e/ and scripts/ are held to theirs on the enterprise tree",
			headerNameWalkRoots(root), headerNameFloorRoots(root))
	}
	for _, failure := range headerNameFloorFailures(src, headerNameFloorRoots(root)) {
		t.Errorf("%s (%s)", failure, src.unread())
	}
	violations, definitions := headerNameViolations(src)
	if definitions != 2 {
		t.Errorf("found %d of the two definitions in %s: the guard's home no longer matches the tree (%s)", definitions, headerNameHome, src.unread())
	}
	for _, v := range violations {
		t.Error(v)
	}
}

// headerNameFloorFailures names each of the given roots the walk read too
// little of.
func headerNameFloorFailures(src headerNameSources, roots []string) []string {
	var out []string
	for _, root := range roots {
		if got, want := src.perRoot[root], headerNameRootFloors[root]; got < want {
			out = append(out, fmt.Sprintf("the walk read %d non-test .go files under %s/, want at least %d: it is not reading the tree it guards", got, root, want))
		}
	}
	return out
}

// TestTheHeaderNameGuardCanFire plants each way a second spelling reaches the
// source on the real tree, one at a time, and requires the guard to name it.
//
// The writer plants run at every live writer this tree carries: the portal's
// (ee/, enterprise tree only) and the agent's MCP proxy (platform/, both
// trees). So on a community-mirror checkout every plant shape still runs
// against a real writer, and the guard proves it can fire on the tree it
// guards there, rather than proving nothing because its one writer was
// stripped.
func TestTheHeaderNameGuardCanFire(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	enterprise := headerNameOnEnterpriseTree(root)
	type writer struct{ label, rel, recv string }
	writers := []writer{{"", "platform/agent/mcp_server_handler.go", "req"}}
	if enterprise {
		writers = append([]writer{{"", "ee/platform/customer-portal/api/hitl_approvals.go", "proxyReq"}}, writers...)
		writers[1].label = " (community writer)"
	} else {
		writers[0].label = " (community writer)"
		t.Logf("a community-mirror checkout: the ee/ writer is stripped, so the writer plants run at %s only", writers[0].rel)
	}
	type plant struct{ name, rel, from, to, want string }
	var plants []plant
	for _, w := range writers {
		canonical := w.recv + ".Header.Set(serviceauth.ServiceIDHeader, serviceauth.ClientID)"
		plants = append(plants,
			plant{"the canonical spelling at the live writer" + w.label, w.rel, canonical,
				w.recv + `.Header.Set("X-Internal-Service-ID", serviceauth.ClientID)`, `"X-Internal-Service-ID"`},
			plant{"a lower-case spelling at the live writer" + w.label, w.rel, canonical,
				w.recv + `.Header.Set("x-internal-service-id", serviceauth.ClientID)`, `"x-internal-service-id"`},
			plant{"the token header in another case" + w.label, w.rel, w.recv + ".Header.Set(serviceauth.ServiceTokenHeader,",
				w.recv + `.Header.Set("X-INTERNAL-SERVICE-TOKEN",`, `"X-INTERNAL-SERVICE-TOKEN"`},
			plant{"the stem concatenated with a suffix" + w.label, w.rel, canonical,
				w.recv + `.Header.Set("X-Internal-Service-"+"ID", serviceauth.ClientID)`, `"X-Internal-Service-"`},
			plant{"a raw string literal" + w.label, w.rel, canonical,
				w.recv + ".Header.Set(`X-Internal-Service-ID`, serviceauth.ClientID)", "`X-Internal-Service-ID`"},
		)
	}
	plants = append(plants,
		plant{"a reader in the agent", "platform/agent/auth.go", "r.Header.Get(serviceauth.ServiceIDHeader)",
			`r.Header.Get("X-Internal-Service-Id")`, `"X-Internal-Service-Id"`},
		plant{"a second constant in the home file", headerNameHome, "\tServiceTokenHeader = \"X-Internal-Service-Token\"\n",
			"\tServiceTokenHeader = \"X-Internal-Service-Token\"\n\tlegacyTokenHeader  = \"X-Internal-Service-Token\"\n", `"X-Internal-Service-Token"`},
	)
	for _, c := range plants {
		t.Run(c.name, func(t *testing.T) {
			src := parseHeaderNameSources(t, root, headerNameWalkRoots(root)...)
			raw, err := os.ReadFile(filepath.Join(root, c.rel)) //nolint:gosec // the repo's own files
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(raw), c.from) != 1 {
				t.Fatalf("%s no longer contains %q exactly once; re-point the plant", c.rel, c.from)
			}
			planted, err := parser.ParseFile(src.fset, c.rel, strings.Replace(string(raw), c.from, c.to, 1), 0)
			if err != nil {
				t.Fatalf("the plant does not parse: %v", err)
			}
			src.files[c.rel] = planted
			violations, _ := headerNameViolations(src)
			for _, v := range violations {
				if strings.HasPrefix(v, c.rel+":") && strings.Contains(v, c.want) {
					return
				}
			}
			t.Fatalf("the guard did not report %s in %s: %v", c.want, c.rel, violations)
		})
	}

	t.Run("a walk that reads nothing fails the floor", func(t *testing.T) {
		src := parseHeaderNameSources(t, t.TempDir())
		if failures := headerNameFloorFailures(src, headerNameRoots); len(failures) != len(headerNameRoots) {
			t.Fatalf("an empty walk passed the floor of some root: %v", failures)
		}
		if _, definitions := headerNameViolations(src); definitions == 2 {
			t.Fatal("an empty walk found both definitions")
		}
	})

	t.Run("a walk that lost one root fails that root's floor", func(t *testing.T) {
		// Every root held to a floor on this tree: all six on the enterprise
		// tree, platform/, examples/ and sdk/ on a mirror.
		floorRoots := headerNameFloorRoots(root)
		for _, lost := range floorRoots {
			var kept []string
			for _, r := range headerNameWalkRoots(root) {
				if r != lost {
					kept = append(kept, r)
				}
			}
			failures := headerNameFloorFailures(parseHeaderNameSources(t, root, kept...), floorRoots)
			if len(failures) != 1 || !strings.Contains(failures[0], " under "+lost+"/,") {
				t.Errorf("a walk without %s/ reported %v, want exactly that root's floor", lost, failures)
			}
		}
	})

	t.Run("a symlinked directory is counted and named, not entered", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "platform", "real"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "platform", "real", "x.go"), []byte("package real\nconst h = \"X-Internal-Service-ID\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(dir, "platform", "real"), filepath.Join(dir, "platform", "linked")); err != nil {
			t.Fatal(err)
		}
		src := parseHeaderNameSources(t, dir, "platform")
		if len(src.symlinkedDirs) != 1 || src.symlinkedDirs[0] != "platform/linked" {
			t.Fatalf("symlinked directories = %v, want [platform/linked]", src.symlinkedDirs)
		}
		if !strings.Contains(src.unread(), "platform/linked") {
			t.Fatalf("the unread report does not name the symlinked directory: %s", src.unread())
		}
		if _, entered := src.files["platform/linked/x.go"]; entered {
			t.Fatal("the walk followed the symlink")
		}
		if v, _ := headerNameViolations(src); len(v) != 1 {
			t.Fatalf("the real directory's literal was reported %d times, want once: %v", len(v), v)
		}
	})
}
