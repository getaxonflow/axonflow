// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package gocensus loads this repository's own Go source, type-checked, for
// the source censuses that assert a property over every package of every
// module in the checkout.
//
// Two censuses use it: the principal-comparison census in
// platform/shared/identity (#3878) and the legacy-freeze writer census in
// platform/shared/legacyfreeze (#4084). Both need the same three things - the
// set of modules to read, the (module, tag set) pairs the go command can list
// in this checkout, and a type-checker fed by export data. It was written for
// the first and extracted when the second arrived, because a census carrying
// its own copy of the second would be the one that disagreed with the other
// about which configurations exist.
//
// # WHY IT USES EXPORT DATA RATHER THAN x/tools
//
// go/packages would be the natural tool and would add golang.org/x/tools as a
// direct dependency of the module that syncs to the community mirror. The
// stdlib route - `go list -deps -export` for the export data, then
// importer.ForCompiler with a lookup - needs nothing outside the standard
// library and costs about three seconds per module against a warm build cache.
//
// IT IS TEST SUPPORT. It runs the go command and takes a testing.TB; nothing
// in a shipping binary imports it.
package gocensus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Package is the subset of `go list -json` a census reads.
type Package struct {
	ImportPath      string
	Dir             string
	Export          string
	GoFiles         []string
	CompiledGoFiles []string
	Module          *struct{ Path string }
	Error           *struct{ Err string }
}

// goList runs `go list` in dir and decodes its JSON stream.
func goList(dir, tags string, args ...string) ([]Package, error) {
	full := []string{"list", "-json"}
	if tags != "" {
		full = append(full, "-tags", tags)
	}
	full = append(full, args...)
	cmd := exec.Command("go", full...)
	cmd.Dir = dir
	// GOFLAGS is cleared so an ambient -mod or -tags from the parent run
	// cannot change what the child resolves. Same reason the mutation gate
	// clears it.
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go %s in %s: %v\n%s", strings.Join(full, " "), dir, err, errb.String())
	}
	dec := json.NewDecoder(&out)
	var pkgs []Package
	for {
		var p Package
		err := dec.Decode(&p)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decoding go list output from %s: %w", dir, err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

// Module holds what is needed to type-check the packages of one module under
// one build tag set, so a caller can scan the whole module or hand one package
// a synthetic file.
type Module struct {
	Fset     *token.FileSet
	Importer types.Importer
	// Packages are the module's own packages, as `go list ./...` reports them.
	// A package the go command could not load carries its Error rather than
	// being dropped, so a caller can report it instead of scanning around it.
	Packages []Package
}

// Load resolves export data for one module under one tag set.
func Load(modDir, tags string) (*Module, error) {
	deps, err := goList(modDir, tags, "-deps", "-export", "./...")
	if err != nil {
		return nil, err
	}
	exportOf := make(map[string]string, len(deps))
	for _, p := range deps {
		if p.Export != "" {
			exportOf[p.ImportPath] = p.Export
		}
	}
	own, err := goList(modDir, tags, "./...")
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	return &Module{
		Fset:     fset,
		Packages: own,
		Importer: importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
			f, ok := exportOf[path]
			if !ok {
				return nil, fmt.Errorf("no export data for %q", path)
			}
			return os.Open(f)
		}),
	}, nil
}

// Dir returns the source directory of a package in this module, or "" when
// the module does not hold it.
func (m *Module) Dir(importPath string) string {
	for i := range m.Packages {
		if m.Packages[i].ImportPath == importPath {
			return m.Packages[i].Dir
		}
	}
	return ""
}

// Parse parses one package's non-test files, plus any extra sources supplied
// as name/content pairs.
//
// THE EXTRA SOURCES ARE HOW A CENSUS IS PROVED ABLE TO FIND ANYTHING. They are
// parsed from memory and never written to the tree: a harness that plants a
// defect by editing a file in a shared clone can be killed between the plant
// and the restore, and the next run then treats the plant as the baseline.
//
// TEST FILES ARE OUT OF SCOPE, and that is a deliberate boundary rather than a
// gap: what a census asserts is a property of what ships.
func (m *Module) Parse(importPath string, extra map[string]string) ([]*ast.File, *Package, error) {
	var pkg *Package
	for i := range m.Packages {
		if m.Packages[i].ImportPath == importPath {
			pkg = &m.Packages[i]
			break
		}
	}
	if pkg == nil {
		return nil, nil, fmt.Errorf("package %q is not in this module", importPath)
	}
	names := pkg.CompiledGoFiles
	if len(names) == 0 {
		names = pkg.GoFiles
	}
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := name
		if !filepath.IsAbs(path) {
			path = filepath.Join(pkg.Dir, name)
		}
		f, err := parser.ParseFile(m.Fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, nil, err
		}
		files = append(files, f)
	}
	for name, src := range extra {
		f, err := parser.ParseFile(m.Fset, filepath.Join(pkg.Dir, name), src, parser.SkipObjectResolution)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing planted source %s: %w", name, err)
		}
		files = append(files, f)
	}
	return files, pkg, nil
}

// RepoRoot walks up from the working directory to the checkout root.
//
// SYMLINKS ARE RESOLVED. On macOS /tmp is a symlink to /private/tmp, and the
// community-mirror simulation stages into exactly such a path; an unresolved
// root there produces module directories the go command computes differently,
// which is the failure the mutation gate already paid for once.
func RepoRoot(t testing.TB) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if resolved, rerr := filepath.EvalSymlinks(wd); rerr == nil {
		wd = resolved
	}
	for dir := wd; ; {
		if _, statErr := os.Stat(filepath.Join(dir, "platform", "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no checkout root above %s: nothing on the way up contains platform/go.mod", wd)
		}
		dir = parent
	}
}

// DiscoverModules returns every module directory in the checkout whose go.mod
// IS, or REQUIRES, one of targets, keyed by module path.
//
// THE FILTER IS THE MODULE GRAPH, NOT A LIST. A module that neither is nor
// requires a target cannot have anything the target defines in scope, so the
// filter is sound; a hand-written list would be a census bounded by the day it
// was written, which is what the nested-module guard one directory over exists
// to say.
func DiscoverModules(t testing.TB, root string, targets ...string) map[string]string {
	t.Helper()
	if len(targets) == 0 {
		t.Fatal("DiscoverModules needs at least one target module; with none, every module is out of the domain")
	}
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata", ".venv":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		text := string(src)
		modPath := modulePathOf(text)
		if modPath == "" {
			return fmt.Errorf("%s declares no module path", path)
		}
		if !reachesAny(modPath, text, targets) {
			return nil
		}
		if prior, dup := out[modPath]; dup {
			return fmt.Errorf("two go.mod files declare module %q: %s and %s", modPath, prior, path)
		}
		out[modPath] = filepath.Dir(path)
		return nil
	})
	if err != nil {
		t.Fatalf("discovering modules under %s: %v", root, err)
	}
	return out
}

// reachesAny reports whether a module IS, or REQUIRES, one of targets.
//
// IT MATCHES A WHOLE PATH, NOT A SUBSTRING, and the difference is not
// pedantry. A substring test pulls in
// github.com/getaxonflow/axonflow/platform/aws-marketplace/... - whose own
// module path contains "axonflow/platform" and which requires neither module -
// and then reports that unrelated module's missing go.sum entries as a census
// failure. Reading a require line for an exact path is the only test that says
// what it means.
func reachesAny(modPath, gomod string, targets []string) bool {
	isTarget := func(p string) bool {
		for _, t := range targets {
			if p == t {
				return true
			}
		}
		return false
	}
	if isTarget(modPath) {
		return true
	}
	for _, line := range strings.Split(gomod, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "require" || fields[0] == "replace" {
			fields = fields[1:]
		}
		if len(fields) == 0 {
			continue
		}
		if isTarget(fields[0]) {
			return true
		}
	}
	return false
}

func modulePathOf(gomod string) string {
	for _, line := range strings.Split(gomod, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// SortedKeys returns a module map's keys in order, so a census reads modules
// in the same order on every run and its failure messages are stable.
func SortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TagSets are the build configurations a census reads: the community build and
// the enterprise build. A property of one is not a property of the other.
var TagSets = []string{"", "enterprise"}

// EEModule is the enterprise tree's root module. Its presence is how a census
// tells an enterprise checkout from a community-mirror one: the sync strips
// ee/ wholesale, and the two checkouts have genuinely different sets of
// buildable configurations.
const EEModule = "axonflow/ee"

// unscannableEnterprise and unscannableMirror are the (module, tag set) pairs
// that CANNOT be listed, per checkout shape, with the reason.
//
// # WHY THIS IS DECLARED PER SHAPE RATHER THAN SWALLOWED
//
// A module a census silently stopped reading is a module it reports as clean.
// But a single list would be wrong in one of the two checkouts, and the
// difference is real rather than incidental:
//
//   - in the ENTERPRISE repository, ee/platform/license-server has no
//     community configuration, because ee/platform/agent/license has every
//     file behind `//go:build enterprise`;
//   - on the COMMUNITY MIRROR, the platform module has no ENTERPRISE
//     configuration. The sync REMOVES every `//go:build enterprise` file
//     (470 of them) after the rsync chain, and fourteen packages are left
//     imported by files that survived while every file they hold is gone -
//     `axonflow/platform/agent` imports `agent/circuitbreaker`, `agent/hitl`,
//     `agent/rbi`, `orchestrator/ojk` and ten more, each reported as "build
//     constraints exclude all Go files". So `go list -tags enterprise ./...`
//     cannot resolve the module there at all.
//
// BOTH HALVES OF THAT WERE FOUND BY RUNNING SOMETHING, and the second was
// found by running the RIGHT thing. The principal-comparison census's first
// version failed on a mirror-shaped tree with eleven rows reported stale - a
// guard that syncs to the mirror has to prove itself on the mirror's own
// inputs. But the tree it failed on was a hand-rolled rsync, which is a
// simulation with its own idea of the rules: it did not model the build-tag
// strip, so it attributed the failure to
// `cmd/orchestrator/imports_enterprise.go` importing a stripped directory. On
// the tree `scripts/ci/simulate-community-mirror.sh` actually stages, that file
// is itself enterprise-tagged and therefore gone, and the mechanism is the one
// above. Same conclusion, different cause - and a reason that misstates the
// mechanism sends the next reader to the wrong file.
//
// A CENSUS MUST ASSERT EACH ROW IN BOTH DIRECTIONS: a declared pair that starts
// listing cleanly is a failure, so the list cannot outlive its reason.
var unscannableEnterprise = map[string]string{
	"axonflow/ee/platform/license-server|": "the ee tree is enterprise-only - ee/platform/agent/license has every " +
		"file behind `//go:build enterprise`, so this module has no community configuration to scan. Its enterprise " +
		"configuration is scanned and is where its packages exist",
}

var unscannableMirror = map[string]string{
	"axonflow/platform|enterprise": "the community sync REMOVES every `//go:build enterprise` file after the " +
		"rsync chain, leaving fourteen packages imported by surviving files while every file they hold is gone " +
		"(agent/circuitbreaker, agent/hitl, agent/rbi, orchestrator/ojk and ten more, each \"build constraints " +
		"exclude all Go files\"), so `go list -tags enterprise ./...` cannot resolve the module there at all. Its " +
		"community configuration IS scanned; the sites behind that constraint are not present in that tree to be " +
		"compared against. Verified against the tree scripts/ci/simulate-community-mirror.sh stages, not against a " +
		"hand-rolled rsync - see the note on unscannableEnterprise",
}

// CheckoutShape names which of the two trees this is, from the module domain
// rather than from a path or an environment variable.
func CheckoutShape(modules map[string]string) string {
	if _, enterprise := modules[EEModule]; enterprise {
		return "enterprise"
	}
	return "community mirror"
}

// Unscannable returns the (module|tags) pairs this checkout's shape cannot
// list, keyed "module|tags", with the reason for each.
func Unscannable(modules map[string]string) map[string]string {
	if CheckoutShape(modules) == "enterprise" {
		return unscannableEnterprise
	}
	return unscannableMirror
}
