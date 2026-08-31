package policy

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// callHit is one matched call, with the line it was found on.
type callHit struct {
	key  string
	line int
}

// callSiteCensusPath is the artifact this test and the ADR-065 plane model both
// read.
const callSiteCensusPath = "../../decision/legacycompile/legacy_call_sites.tsv"

// censusRow is one census entry: whether the call passes ActionOverrides, and
// which edition's tree carries the file.
type censusRow struct {
	overrides bool
	edition   string
}

// enterpriseSourceRe is the community sync's OWN definition of enterprise-only
// source: the build-constraint scan in .github/workflows/sync-community-repo.yml
// and .github/scripts/check-enterprise-leak.sh delete every Go file it matches
// before the mirror is published. The expression is kept byte-identical at
// every site by tests/regression-test-required/enterprise_tag_regex_single_definition_test.sh,
// because a classifier that drifts from the sync classifies a different mirror.
var enterpriseSourceRe = regexp.MustCompile(`(?m)^//go:build enterprise|^// \+build enterprise`)

// sourceEdition classifies a repository-relative Go path by the community
// sync's two DELETION mechanisms. A test aware of only one of them (this file
// used to know that ee/ is absent on the mirror) reports a stripped file as a
// deleted one: ee/ is excluded wholesale, *_enterprise.go and
// *_enterprise_test.go are deleted by name, and any file whose build
// constraint selects the enterprise build is deleted by the scan. The rsync
// chain's directory exclusions (platform/fptpcorpus/, platform/monitoring/,
// ...) are not modelled; a censused call site inside one of those would be
// caught by the mirror simulation lane in test.yml. Everything else reaches
// the mirror and is "community".
func sourceEdition(root, rel string) (string, error) {
	if strings.HasPrefix(rel, "ee/") || strings.HasSuffix(rel, "_enterprise.go") || strings.HasSuffix(rel, "_enterprise_test.go") {
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

// treeIsCommunityMirror reports whether this checkout is the public mirror,
// which the sync produces without ee/. The same discriminator is used by the
// repository's workflow guards.
func treeIsCommunityMirror(root string) bool {
	_, err := os.Stat(filepath.Join(root, "ee"))
	return err != nil
}

// evaluatorMethods are the four entry points through which the LEGACY policy
// substrate is evaluated. Every enforcement plane ADR-065 Phase 4 cuts over
// independently reaches one of them.
var evaluatorMethods = []string{
	"EvaluateRequest",         // shared static engine, request phase
	"EvaluateResponse",        // shared static engine, response phase
	"EvaluateDynamicPolicies", // the orchestrator's database-backed dynamic engine
	"EvaluatePolicy",          // TierAwarePolicyEngine, the proxy tier
}

// TestLegacyCallSiteCensusIsComplete pins the ADR-065 plane model to the tree.
//
// # Why this exists, stated plainly because it was learned the hard way
//
// platform/decision/legacycompile carries a per-plane model - which substrate
// each plane reads, in which phase, under which posture - and that model is the
// SHADOW GATE'S DENOMINATOR. A plane missing from it is a population nobody
// measures; a plane invented for it measures nothing while reading as coverage.
//
// The first version of that model was written by reading call sites and doc
// comments, and independent review found it wrong in both directions: it
// carried a `connector_execution` plane with no evaluation call site anywhere
// in the tree, gave MAP a static substrate on the strength of a stale doc
// comment (the response processor's only caller is the orchestrator's
// /api/v1/process handler), gave /decide a dynamic substrate although it passes
// runDynamicPolicy=false, and omitted the proxy request pass and the tier
// engine's second call site entirely.
//
// A claim about which code paths exist cannot be pinned by a comment. It can be
// pinned by a census, which is what this is: the checked-in TSV names every
// call site, this test proves the TSV describes the tree, and a test in the
// decision module proves the plane model describes the TSV. Adding or removing
// a call site fails HERE, on the PR that does it.
func TestLegacyCallSiteCensusIsComplete(t *testing.T) {
	want := readCensus(t, callSiteCensusPath)
	got := scanCallSites(t)
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	mirror := treeIsCommunityMirror(root)

	if len(want) == 0 {
		t.Fatalf("%s is empty; an empty census would let this test pass while asserting nothing", callSiteCensusPath)
	}
	// Anti-vacuity derived from the tree, not calibrated: the scan must find
	// call sites at all, and it must find all four evaluators. A scanner that
	// silently stopped matching would otherwise report an empty tree and only
	// the "missing from the census" arm would fire, which reads as a deletion
	// rather than as a broken scanner.
	if len(got) == 0 {
		t.Fatal("the scan found no legacy policy evaluation call sites; the scanner is not looking at the tree")
	}
	seenEvaluators := map[string]bool{}
	for k := range got {
		seenEvaluators[strings.Split(k, "\t")[1]] = true
	}
	for _, m := range evaluatorMethods {
		if !seenEvaluators[m] {
			t.Fatalf("the scan found no call to %s anywhere; either it was removed - which is a plane disappearing - or the scanner stopped matching it", m)
		}
	}

	// The edition column decides what a missing file MEANS. On the public
	// mirror an enterprise-only file is absent by construction, and reporting
	// it as a deletion would make this test red on every mirror pull request
	// for a file that is exactly where it should be; a community file absent
	// anywhere is a deletion. The column is only allowed to say that because
	// the enterprise tree, where every censused file exists, verifies it
	// against the file's real build constraint on every run: a row labelled
	// community in an enterprise-tagged file would have been an expected
	// absence on the mirror hiding a real one.
	var missing, extra, overrideMismatch, editionMismatch, strippedButPresent []string
	stripped := 0
	for k, row := range want {
		file := strings.Split(k, "\t")[0]
		if _, ok := got[k]; !ok {
			if mirror && row.edition == "enterprise" {
				if _, statErr := os.Stat(filepath.Join(root, file)); statErr == nil {
					strippedButPresent = append(strippedButPresent, k)
					continue
				}
				stripped++
				continue
			}
			missing = append(missing, k)
			continue
		}
		actual, err := sourceEdition(root, file)
		if err != nil {
			t.Fatalf("classifying %s: %v", file, err)
		}
		if actual != row.edition {
			editionMismatch = append(editionMismatch, fmt.Sprintf("%s: census says edition=%s, the file is %s", k, row.edition, actual))
		}
	}
	for k, gotOverrides := range got {
		row, ok := want[k]
		if !ok {
			extra = append(extra, k)
			continue
		}
		if row.overrides != gotOverrides {
			overrideMismatch = append(overrideMismatch, fmt.Sprintf("%s: census says passes_action_overrides=%t, the call site says %t",
				k, row.overrides, gotOverrides))
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	sort.Strings(overrideMismatch)
	sort.Strings(editionMismatch)
	sort.Strings(strippedButPresent)

	if len(editionMismatch) > 0 {
		t.Fatalf("%d census row(s) name the wrong edition:\n  %s\n\n"+
			"The edition column is what lets the community mirror tell a stripped file from a deleted one, so it must\n"+
			"say what the file's build constraint says (the sync's rule: ee/, *_enterprise.go, or a `//go:build enterprise` line).",
			len(editionMismatch), strings.Join(editionMismatch, "\n  "))
	}
	if len(strippedButPresent) > 0 {
		t.Fatalf("this is a community tree and %d census row(s) labelled enterprise cite a file that IS present, yet the scan found no call in it:\n  %s\n\n"+
			"Either the file is mislabelled enterprise, or the call site moved. The label is verified in the enterprise tree, so fix it there.",
			len(strippedButPresent), strings.Join(strippedButPresent, "\n  "))
	}
	if mirror && stripped > 0 {
		t.Logf("community tree: %d enterprise-only census row(s) are absent, as the sync's build-tag strip makes them", stripped)
	}

	if len(extra) > 0 {
		t.Fatalf("the tree has %d legacy policy evaluation call site(s) the census does not record:\n  %s\n\n"+
			"Each one is an enforcement surface the ADR-065 shadow gate does not measure. Add it to %s AND give it a\n"+
			"plane in platform/decision/legacycompile/plane.go, or the migration will cut over a path nobody diffed.",
			len(extra), strings.Join(extra, "\n  "), callSiteCensusPath)
	}
	if len(missing) > 0 {
		t.Fatalf("the census records %d call site(s) that no longer exist in the tree:\n  %s\n\n"+
			"A census entry with no code behind it makes the plane model claim coverage of something that is not there.",
			len(missing), strings.Join(missing, "\n  "))
	}
	if len(overrideMismatch) > 0 {
		// The posture lever is per-CALL-SITE, not per-engine: a plane that does
		// not pass EvalOptions.ActionOverrides enforces the stored action while
		// its neighbour enforces the deployment posture. The shadow diff
		// attributes a displaced action to the posture rather than to the
		// compiler, so getting this wrong for one plane reports a difference
		// the migration tooling caused as one the substrate had.
		t.Fatalf("%d call site(s) disagree with the census about passing ActionOverrides:\n  %s",
			len(overrideMismatch), strings.Join(overrideMismatch, "\n  "))
	}
	t.Logf("census agrees with the tree on %d legacy policy evaluation call site(s), including which pass ActionOverrides and which edition carries each", len(got))
}

// TestSourceEditionFollowsTheSyncsRules pins the classifier to the three ways
// the community sync strips a file, in both directions, so a regression in
// any one of them cannot be mistaken for "the tree has no such file".
func TestSourceEditionFollowsTheSyncsRules(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("ee/platform/x.go", "package x\n")
	write("platform/a/plain_enterprise.go", "package a\n")
	write("platform/a/tagged.go", "//go:build enterprise\n\npackage a\n")
	write("platform/a/legacy_tagged.go", "// +build enterprise\n\npackage a\n")
	write("platform/a/negated.go", "//go:build !enterprise\n\npackage a\n")
	write("platform/a/mentions.go", "package a\n\n// A comment that mentions //go:build enterprise is not a constraint.\n")
	write("platform/a/community.go", "package a\n")
	cases := map[string]string{
		"ee/platform/x.go":               "enterprise",
		"platform/a/plain_enterprise.go": "enterprise",
		"platform/a/tagged.go":           "enterprise",
		"platform/a/legacy_tagged.go":    "enterprise",
		"platform/a/negated.go":          "community",
		"platform/a/mentions.go":         "community",
		"platform/a/community.go":        "community",
	}
	for rel, want := range cases {
		got, err := sourceEdition(root, rel)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if got != want {
			t.Errorf("%s: classified %s, want %s", rel, got, want)
		}
	}
	if _, err := sourceEdition(root, "platform/a/absent.go"); err == nil {
		t.Fatal("a file that does not exist was classified instead of reported")
	}
	if !treeIsCommunityMirror(filepath.Join(root, "platform")) || treeIsCommunityMirror(root) {
		t.Fatal("the mirror discriminator does not follow the presence of ee/")
	}
}

// scanCallSites walks platform/ and ee/ and returns every call to one of the
// four evaluators, keyed "file\tevaluator\tfunction".
//
// Deliberately excluded: _test.go files, interface method declarations and the
// method definitions themselves. Included: everything else, so a call added
// inside a closure or a helper still shows up.
func scanCallSites(t *testing.T) map[string]bool {
	t.Helper()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	funcRe := regexp.MustCompile(`^func (\([^)]*\) )?([A-Za-z0-9_]+)`)
	callRes := map[string]*regexp.Regexp{}
	for _, m := range evaluatorMethods {
		callRes[m] = regexp.MustCompile(`\.` + m + `\(`)
	}

	out := map[string]bool{}
	for _, dir := range []string{"platform", "ee"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			// The community mirror has no ee/. A missing tree is not a finding.
			continue
		}
		err := filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				// The decision module is the CONSUMER of this census, not a
				// subject of it, and it contains the evaluator names in prose.
				if strings.HasSuffix(path, "/platform/decision") || info.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			cur := "(package level)"
			var fileLines []string
			var hits []callHit
			lineNo := 0
			for sc.Scan() {
				line := sc.Text()
				fileLines = append(fileLines, line)
				lineNo++
				if m := funcRe.FindStringSubmatch(line); m != nil {
					cur = m[2]
				}
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(line, "func ") {
					continue
				}
				for name, re := range callRes {
					if re.MatchString(line) {
						hits = append(hits, callHit{key: rel + "\t" + name + "\t" + cur, line: lineNo})
					}
				}
			}
			if err := sc.Err(); err != nil {
				return err
			}
			// Whether the call passes EvalOptions.ActionOverrides is read from
			// the CALL, by looking at the option literal it is written with. A
			// window rather than a parse, and bounded so a distant unrelated
			// mention cannot be mistaken for this call's.
			for _, h := range hits {
				end := h.line + 40
				if end > len(fileLines) {
					end = len(fileLines)
				}
				out[h.key] = out[h.key] || strings.Contains(strings.Join(fileLines[h.line-1:end], "\n"), "ActionOverrides")
				if _, seen := out[h.key]; !seen {
					out[h.key] = false
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", base, err)
		}
	}
	return out
}

func readCensus(t *testing.T, path string) map[string]censusRow {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatalf("%s is empty", path)
	}
	if h := sc.Text(); h != "plane\tevaluator\tfile\tfunction\tpasses_action_overrides\tedition" {
		t.Fatalf("%s header is %q, want \"plane\\tevaluator\\tfile\\tfunction\\tpasses_action_overrides\\tedition\"", path, h)
	}
	out := map[string]censusRow{}
	for sc.Scan() {
		line := strings.TrimRight(strings.TrimSpace(sc.Text()), "\r")
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 6 {
			t.Fatalf("%s: row %q has %d fields, want 6", path, line, len(fields))
		}
		switch fields[4] {
		case "yes", "no":
		default:
			t.Fatalf("%s: row %q has passes_action_overrides=%q, want yes or no", path, line, fields[4])
		}
		switch fields[5] {
		case "community", "enterprise":
		default:
			t.Fatalf("%s: row %q has edition=%q, want community or enterprise", path, line, fields[5])
		}
		out[fields[2]+"\t"+fields[1]+"\t"+fields[3]] = censusRow{overrides: fields[4] == "yes", edition: fields[5]}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return out
}
