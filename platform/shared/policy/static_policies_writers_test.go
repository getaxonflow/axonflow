// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// NO POLICY ROW IS SEEDED OUTSIDE A MIGRATION (PRD v11 §1.2, #4126 D4)
//
// The shipped policies are compiled from the rows the migrations write
// (TestDetectorCensusMatchesTheMigratedDatabase), and a row anything else
// writes is a row nobody shipped: in v11 it authors no verdict, and the FinCrime
// pack's seed.sh was exactly such a writer until #4126 made the pack a typed
// document. This test finds every file that writes static_policies and holds
// each one to a ruled class, so a new writer - a pack that goes back to
// seeding, a demo bundle, a product file - fails on the pull request that adds
// it. The migrations themselves are held by id, per deployment mode, by
// TestMigrationChainAppliesCleanly_RealPostgres in the migrations gate.

// staticPoliciesWrite matches a statement that writes static_policies.
var staticPoliciesWrite = regexp.MustCompile(`(?i)\b(insert\s+into|update|delete\s+from)\s+(public\.)?static_policies\b`)

// seedWriterClass is a ruled class of file that may write static_policies. The
// first class that matches a path classifies it.
type seedWriterClass struct {
	name  string
	match func(path string) bool
}

var seedWriterClasses = []seedWriterClass{
	// The shipped rows, held by id by the census test and the migrations gate.
	{"migration", func(p string) bool { return strings.HasPrefix(p, "migrations/") }},
	// The migrations v10.2.0 shipped, byte for byte, which the #3894 upgrade test
	// replays on the ephemeral database it provisions. platform/agent/upgradepin
	// holds each to its sha256 at the v10.2.0 tag, so they are shipped rows too.
	{"pinned v10.2.0 migration", func(p string) bool {
		return strings.HasPrefix(p, "platform/agent/testdata/v10_2_0/migrations/") ||
			strings.HasPrefix(p, "ee/platform/agent/testdata/v10_2_0/migrations/")
	}},
	// Rows a test builds on the ephemeral database it provisions.
	{"Go test fixture", func(p string) bool { return strings.HasSuffix(p, "_test.go") }},
	// Rows a runtime suite builds on its own ephemeral stack.
	{"runtime suite fixture", func(p string) bool { return strings.HasPrefix(p, "runtime-e2e/") }},
	// Text the readiness-gate lint matches in a suite's shape; never run
	// against a database.
	{"readiness-gate lint and its fixtures", func(p string) bool {
		return p == "scripts/e2e/readiness_gate_shape.py" ||
			p == "scripts/e2e/lint-readiness-gate-shape_test.sh" ||
			strings.HasPrefix(p, "scripts/e2e/fixtures/readiness-gate-shape/")
	}},
	// Prose that shows a statement; never executed.
	{"documentation", func(p string) bool { return strings.HasSuffix(p, ".md") }},
}

// seedWriterFiles are single files ruled one by one, each with its reason.
var seedWriterFiles = map[string]string{
	"platform/agent/static_policy_repository.go": "the legacy static-policy write route, which answers " +
		"409 LEGACY_POLICY_WRITE_FROZEN except on an owner-pool deployment (#4113)",
	"scripts/v9_rollback/094_rollback.sql": "the operator's rollback of migration 094: it clears the " +
		"org_id 094 backfilled on existing rows and creates none",
}

// seedWriterSkippedDirs are directories no tracked writer lives in: VCS
// metadata and installed or built artifacts.
var seedWriterSkippedDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".next": true, "dist": true,
	"coverage": true, ".venv": true, "target": true,
}

// classifySeedWriter names the ruled class or file rule a writer falls under.
func classifySeedWriter(path string) (string, bool) {
	if _, ok := seedWriterFiles[path]; ok {
		return path, true
	}
	for _, c := range seedWriterClasses {
		if c.match(path) {
			return c.name, true
		}
	}
	return "", false
}

// seedWriterViolations classifies writers and returns why any may not write:
// a writer in no ruled class. It also returns how many writers each rule
// classified.
func seedWriterViolations(writers []string) ([]string, map[string]int) {
	used := map[string]int{}
	var out []string
	for _, w := range writers {
		rule, ok := classifySeedWriter(w)
		if !ok {
			out = append(out, fmt.Sprintf("%s writes static_policies and is in no ruled class. A policy row is shipped by a "+
				"migration and nothing else (PRD v11 §1.2); a pack is a typed document (§1.9), never seeded rows", w))
			continue
		}
		used[rule]++
	}
	return out, used
}

// communityMirrorShape reports whether root is the community mirror: the sync
// strips the ee/ tree, and with it every Enterprise-only path, so a checkout
// without ee/ is the mirror (as principal_comparison_census_test.go reads it).
func communityMirrorShape(root string) bool {
	_, err := os.Stat(filepath.Join(root, "ee"))
	return errors.Is(err, fs.ErrNotExist)
}

// staleSeedWriterRules returns the ruled classes and file rules that classified
// no writer: a rule that matches nothing is a stale exemption, and one that is
// never exercised cannot show it still classifies what it names.
//
// On the community mirror it judges none of them, and returns why instead. The
// mirror is a strict subset of the enterprise tree, which judges every rule
// exactly on every pull request, so a rule empty only on the mirror names what
// the sync strips: the runtime suites, the readiness-gate fixtures and the v9
// rollback scripts all go. A list of the stripped roots here would be a second
// copy of the sync's exclusions. Every writer the mirror does carry is still
// classified.
func staleSeedWriterRules(used map[string]int, mirror bool) (stale []string, notRun string) {
	for _, c := range seedWriterClasses {
		if used[c.name] == 0 {
			stale = append(stale, fmt.Sprintf("the %q class classifies no writer; remove it", c.name))
		}
	}
	files := make([]string, 0, len(seedWriterFiles))
	for f := range seedWriterFiles {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		if used[f] == 0 {
			stale = append(stale, fmt.Sprintf("%s no longer writes static_policies; remove its rule", f))
		}
	}
	if !mirror {
		return stale, ""
	}
	return nil, fmt.Sprintf("the stale-rule direction is not run on the community mirror (no ee/ tree): the enterprise "+
		"tree judges every rule exactly on every pull request, and %d rule(s) empty here name what the sync strips", len(stale))
}

// staticPoliciesWriters returns every file under root, slash-separated and
// relative to it, whose text writes static_policies.
func staticPoliciesWriters(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && seedWriterSkippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(b, 0) >= 0 || !staticPoliciesWrite.Match(b) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out, err
}

func TestNoStaticPoliciesWriterOutsideARuledClass(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "migrations", "core")); err != nil {
		t.Fatalf("%s is not the repository root: %v", root, err)
	}
	writers, err := staticPoliciesWriters(root)
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	violations, used := seedWriterViolations(writers)
	for _, v := range violations {
		t.Error(v)
	}
	stale, notRun := staleSeedWriterRules(used, communityMirrorShape(root))
	for _, v := range stale {
		t.Error(v)
	}
	if notRun != "" {
		t.Log(notRun)
	}
}

// The census is a derivation, so it is proved to red: a writer planted outside
// the ruled classes is found and refused, and the same statement in a ruled
// class is not.
func TestTheSeedWriterCensusRedsOnAPlantedWriter(t *testing.T) {
	root := t.TempDir()
	plant := func(rel, body string) { plantSeedWriterFile(t, root, rel, body) }
	insert := "INSERT INTO static_policies (policy_id, name) VALUES ('p', 'P');\n"
	// The retired FinCrime seed, restored.
	plant("ee/policy-packs/fincrime/fincrime_policy_pack_v1.sql", insert)
	plant("platform/agent/seed_rows.go", "const q = `update public.static_policies set enabled = false`\n")
	plant("migrations/core/999_planted.sql", insert)
	plant("docs/example.md", insert)
	plant("node_modules/x/seed.sql", insert)
	plant("README.txt", "static_policies holds the shipped rows\n")
	// Two seed bundles, restored: the one config/seed-data held was retired with
	// its rows (#4138, migrations/enterprise/160), and its class and cap with
	// it, so each is refused on its own.
	plant("config/seed-data/a/bundle.sql", insert)
	plant("config/seed-data/b/bundle.sql", insert)

	writers, err := staticPoliciesWriters(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"config/seed-data/a/bundle.sql",
		"config/seed-data/b/bundle.sql",
		"docs/example.md",
		"ee/policy-packs/fincrime/fincrime_policy_pack_v1.sql",
		"migrations/core/999_planted.sql",
		"platform/agent/seed_rows.go",
	}
	if strings.Join(writers, ",") != strings.Join(want, ",") {
		t.Fatalf("writers found = %v, want %v (node_modules skipped, a mention that writes nothing ignored)", writers, want)
	}
	violations, _ := seedWriterViolations(writers)
	if len(violations) != 4 ||
		!strings.HasPrefix(violations[0], "config/seed-data/a/bundle.sql ") ||
		!strings.HasPrefix(violations[1], "config/seed-data/b/bundle.sql ") ||
		!strings.HasPrefix(violations[2], "ee/policy-packs/fincrime/fincrime_policy_pack_v1.sql ") ||
		!strings.HasPrefix(violations[3], "platform/agent/seed_rows.go ") {
		t.Fatalf("violations = %q, want both restored seed bundles, the restored FinCrime seed and the product-file writer", violations)
	}
}

// plantSeedWriterFile writes body at rel under root, creating its directories.
func plantSeedWriterFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The stale-rule direction reads the checkout's shape. The same tree - one
// migration writer, every other rule empty - is stale on the enterprise shape
// and not judged on the mirror's; and on the mirror's shape a writer outside
// the ruled classes still reds.
func TestTheStaleRuleDirectionReadsTheCheckoutShape(t *testing.T) {
	insert := "INSERT INTO static_policies (policy_id, name) VALUES ('p', 'P');\n"
	census := func(root string) (violations, stale []string, notRun string) {
		writers, err := staticPoliciesWriters(root)
		if err != nil {
			t.Fatal(err)
		}
		violations, used := seedWriterViolations(writers)
		stale, notRun = staleSeedWriterRules(used, communityMirrorShape(root))
		return violations, stale, notRun
	}
	wantStale := len(seedWriterClasses) - 1 + len(seedWriterFiles)

	enterprise := t.TempDir()
	plantSeedWriterFile(t, enterprise, "migrations/core/001_seed.sql", insert)
	plantSeedWriterFile(t, enterprise, "ee/README.md", "the Enterprise tree\n")
	violations, stale, notRun := census(enterprise)
	if len(violations) != 0 || len(stale) != wantStale || notRun != "" {
		t.Fatalf("enterprise shape: violations %q, %d stale (want %d), not-run %q: every empty rule is stale there", violations, len(stale), wantStale, notRun)
	}
	if !strings.Contains(strings.Join(stale, "\n"), `the "runtime suite fixture" class classifies no writer`) {
		t.Errorf("enterprise shape: the stale list %q does not name the empty runtime suite class", stale)
	}

	mirror := t.TempDir()
	plantSeedWriterFile(t, mirror, "migrations/core/001_seed.sql", insert)
	violations, stale, notRun = census(mirror)
	if len(violations) != 0 || len(stale) != 0 || !strings.Contains(notRun, "not run on the community mirror") ||
		!strings.Contains(notRun, fmt.Sprintf("%d rule(s) empty here", wantStale)) {
		t.Fatalf("mirror shape: violations %q, stale %q, not-run %q: the stale direction is reported not run, never failed", violations, stale, notRun)
	}

	plantSeedWriterFile(t, mirror, "platform/agent/seed_rows.go", "const q = `update public.static_policies set enabled = false`\n")
	plantSeedWriterFile(t, mirror, "config/seed-data/a/bundle.sql", insert)
	plantSeedWriterFile(t, mirror, "config/seed-data/b/bundle.sql", insert)
	violations, _, _ = census(mirror)
	if len(violations) != 3 || !strings.HasPrefix(violations[0], "config/seed-data/a/bundle.sql ") ||
		!strings.HasPrefix(violations[1], "config/seed-data/b/bundle.sql ") ||
		!strings.HasPrefix(violations[2], "platform/agent/seed_rows.go ") {
		t.Fatalf("mirror shape: violations %q, want both restored seed bundles and the unclassified writer", violations)
	}
}
