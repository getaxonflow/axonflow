// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package edition owns the inventory of files that exist at BOTH platform/X
// and ee/platform/X, and the rule that decides which of those are a defect.
//
// # WHY THIS EXISTS
//
// platform/agent/Dockerfile overlays ee/platform/agent/<pkg>/* onto
// platform/agent/<pkg>/* for EDITION=enterprise, then builds the whole thing
// from the platform module with -tags enterprise. A file that exists on both
// sides is therefore compiled from the ee copy in the shipped image and from
// the platform copy in every platform-module test. When the two drift, the
// binary customers run has behaviour no test in this tree exercises. That is
// not hypothetical: #3710 (two licence-key decoders accepting different
// base64 dialects) and #3714 (a HITL chokepoint guarding one side's INSERT
// only) are both instances, and #3759 measured a runtime arm applying the
// right ceiling from the copy that had been changed while losing its
// observability to the copy that had not.
//
// Fixing instances while the generator remains is how the class regenerates.
// The durable answer is to remove the duplicate where it is genuinely a
// duplicate, and to REFUSE AN UNDECLARED PAIR everywhere else — which is what
// twin_census.tsv plus TestTwinCensusMatchesTree do.
//
// # WHY A TEXT COMPARISON IS NOT THE GUARD
//
// getPluginCompatibility()'s own comment records that a test comparing two
// copies "was tried and is not sufficient": two copies that are equal and
// wrong pass it, and a reformat breaks it. This package does not compare the
// copies to each other and call that safety. It records a DECISION per pair —
// collapsed, or kept with a reason — and fails on any pair that has no
// decision, on any collapsed pair that comes back, and on any stale row whose
// pair no longer exists. Each kept bucket can only shrink (see the ratchets:
// MaxKeepTwinRows, MaxKeepDriftRows, MaxKeepBoundaryRows).
package edition

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Population classifies how far a pair's two copies have drifted. The three
// values need opposite treatment, which is the whole reason the census
// distinguishes them.
type Population string

const (
	// PopulationIdentical: the two copies are byte-for-byte equal.
	PopulationIdentical Population = "1"

	// PopulationBuildTagOnly: the two copies differ ONLY by //go:build
	// constraint lines and blank lines — constructs that cannot change
	// behaviour. The content compiles in both editions; the constraint decides
	// which build sees the platform copy, and the overlaid image is built with
	// -tags enterprise, so a satisfied constraint is inert there.
	PopulationBuildTagOnly Population = "2"

	// PopulationDiverged: anything else. NOT a twin. Either the intended
	// ADR-066 Decision 5 pattern (community stub against enterprise
	// implementation) or a real divergence that is its own defect. Never
	// collapsed here — deleting one copy of a diverged pair silently picks a
	// winner, and in #3710's case the copy that would have won by tidiness
	// was the one missing the tolerance an operator needs.
	PopulationDiverged Population = "3"
)

// Disposition is the decision recorded for a pair.
type Disposition string

const (
	// DispositionCollapsed: the ee copy has been deleted. The platform copy
	// is the only copy and the overlay resolves to it. The guard fails if an
	// ee copy reappears at this path.
	DispositionCollapsed Disposition = "collapsed"

	// DispositionKeepTwin: population 1 or 2 — the two copies are the same
	// source — but the ee copy cannot leave, because its PACKAGE is forked.
	// Go compiles packages, not files: a twin that other files in the same ee
	// package reference cannot be deleted without breaking that package, and
	// a twin _test.go compiles against the forked implementation beside it,
	// which makes it the only test of the code the image actually ships.
	// These are the rows to drive to zero, and the way to do it is to resolve
	// the package's divergence — after which the twins collapse for free.
	DispositionKeepTwin Disposition = "keep-twin"

	// DispositionKeepDrift: population 3 where BOTH copies are
	// enterprise-only. Two copies of the same enterprise implementation that
	// disagree. This is unintended and is filed as a child of #3725.
	DispositionKeepDrift Disposition = "keep-drift"

	// DispositionKeepBoundary: population 3 where the platform copy is
	// community-visible (untagged) and the ee copy is the enterprise
	// override. This is ADR-066 Decision 5's intended pattern — a community
	// stub against an enterprise implementation — and is NOT duplication.
	DispositionKeepBoundary Disposition = "keep-boundary"
)

// ProposeDisposition derives a pair's disposition FROM THE TREE. The guard
// checks the recorded disposition against this, so a row cannot be downgraded
// (drift relabelled as an intended boundary, say) to slip under a ratchet.
// Only the reason column is human.
func ProposeDisposition(root, platformRel string) (Disposition, Population, int, int, error) {
	if !fileExistsAt(filepath.Join(root, "ee", platformRel)) {
		return DispositionCollapsed, "", 0, 0, nil
	}
	pop, lineDelta, codeDelta, err := Classify(root, platformRel)
	if err != nil {
		return "", "", 0, 0, err
	}
	switch pop {
	case PopulationIdentical, PopulationBuildTagOnly:
		return DispositionKeepTwin, pop, lineDelta, codeDelta, nil
	}
	tagged, err := isEnterpriseOnly(filepath.Join(root, platformRel))
	if err != nil {
		return "", "", 0, 0, err
	}
	if tagged {
		return DispositionKeepDrift, pop, lineDelta, codeDelta, nil
	}
	return DispositionKeepBoundary, pop, lineDelta, codeDelta, nil
}

// enterpriseOnlyRE is the community sync's own definition of "enterprise-only
// source", byte-identical to the expression in sync-community-repo.yml,
// check-enterprise-leak.sh and simulate-community-mirror.sh. Every Go file it
// matches is DELETED from the staged community copy.
//
// It is repeated here rather than approximated because this file classifies
// arbitrary source: a classifier that drifts from the sync's expression
// classifies a different mirror, and nothing else would notice. Pinned by
// tests/regression-test-required/enterprise_tag_regex_single_definition_test.sh.
var enterpriseOnlyRE = regexp.MustCompile(`(?m)^//go:build enterprise|^// \+build enterprise`)

// isEnterpriseOnly reports whether a file is invisible to the community build.
// When the PLATFORM copy is enterprise-only, both copies of the pair are the
// enterprise implementation and any difference between them is drift, not an
// edition boundary.
func isEnterpriseOnly(path string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return enterpriseOnlyRE.Match(b), nil
}

func fileExistsAt(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// Row is one line of twin_census.tsv.
type Row struct {
	PlatformPath string      // repo-relative, e.g. platform/agent/hitl/service.go
	Population   Population  // 1, 2 or 3
	LineDelta    int         // `diff a b | grep -c '^[<>]'`, 0 when identical
	CodeDelta    int         // same count over comment-stripped, gofmt-printed source; -1 when not parseable Go
	Disposition  Disposition // collapsed | keep-twin | keep-drift | keep-boundary
	Reason       string      // why, in one clause
}

// censusHeader is the TSV's first line. It is asserted on load, so a column
// added without updating the readers fails loudly instead of shifting values.
const censusHeader = "platform_path\tpopulation\tline_delta\tcode_delta\tdisposition\treason"

// GeneratorPlaceholderReason is what -update writes for a pair it has never
// seen. It is REFUSED by the guard.
//
// Without this, `-update` launders a bad tree into a passing census: remove one
// keep-drift pair, add a different diverged pair, regenerate, and every check
// passes — the count ratchet is unmoved because it counts ROWS rather than the
// SET, and "every row states a reason" is satisfied by the placeholder the
// generator itself wrote. That is #3810's lesson verbatim (counting alone hides
// a swap). Refusing the placeholder means a new pair cannot enter the census
// without a human writing why, which is the reviewable act the ratchet exists
// to force.
const GeneratorPlaceholderReason = "TODO: state why both copies must exist"

// CensusPath is the census file, relative to the repository root.
const CensusPath = "platform/shared/edition/twin_census.tsv"

// KeptSetDigest pins the SET of kept pairs, not merely how many there are.
//
// The count ratchets cannot see a SWAP: remove one keep-drift pair, add a
// different one, and every count is unmoved. R3 round 1 reproduced exactly that
// and round 2 proved that refusing the generator's placeholder reason only
// raises the bar — a hand-written reason still launders it. This closes it,
// because a digest over the sorted "disposition<TAB>path" lines changes for ANY
// membership change, and `-update` cannot rewrite a Go constant.
//
// It is the same shape as #3810's lesson: prove the SET both ways, because
// counting alone hides a swap.
//
// To change it legitimately: resolve a pair, regenerate, then update this
// constant AND the matching ratchet. The diff then shows exactly which paths
// moved, which is the reviewable act the whole census exists to force.
const KeptSetDigest = "7dafe365fcaa8133660d2fc039b76d1027dad7e9161823661fb5db2f45babdcc"

// KeptSetDigestOf renders the digest of the census's rows.
//
// COLLAPSED ROWS ARE INCLUDED. They were excluded on the argument that they are
// history and history only grows - which made "history only grows" a printed
// bucket rather than a checked one, exactly the shape this package warns about.
// Measured: deleting a collapsed row passed both halves, and so did fabricating
// one. A collapsed row is a load-bearing claim ("this ee copy was removed
// deliberately and must not come back"), and the guard's COLLAPSED PAIR CAME
// BACK / MOVED checks are driven off these rows - so a deleted one silently
// disarms them for that path.
func KeptSetDigestOf(rows []Row) string {
	lines := make([]string, 0, len(rows))
	for _, r := range rows {
		lines = append(lines, string(r.Disposition)+"\t"+r.PlatformPath)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n") + "\n"))
	return hex.EncodeToString(sum[:])
}

// The RATCHETS. Each is the count of its disposition when this lane closed,
// and each may only go DOWN. Raising one to admit a new pair is not a fix, it
// is the class regenerating: resolve the divergence and delete the row.
//
// They are separate because the three populations have different endpoints.
// MaxKeepTwinRows and MaxKeepDriftRows should reach zero — a twin is pure
// duplication and drift between two enterprise copies is a defect.
// MaxKeepBoundaryRows is ADR-066 Decision 5's intended pattern and has no
// reason to reach zero; it is ratcheted anyway because a bucket that is only
// printed is not checked, and a new stub/implementation pair should be a
// deliberate, reviewable act rather than a number nobody watches.
const (
	// MinCollapsedRows is a FLOOR, not a cap: collapsed rows are the record of
	// what this lane removed, and that record may only grow. Deleting one
	// disarms the CAME BACK and MOVED checks for that path.
	MinCollapsedRows = 17

	// 20 since #3593 (2026-09-08): platform/agent/license/tier_limits.go is
	// the ONE self-hosted limits table, untagged in platform/ and
	// enterprise-tagged in ee/ so the overlaid image compiles it - the same
	// deliberate shape as tier_read.go and testing.go, held identical apart
	// from the constraint line by license_pair_byte_identity_test.sh. The
	// reason is recorded on #3725 as the ratchet's doc requires.
	MaxKeepTwinRows     = 20
	MaxKeepDriftRows    = 26
	MaxKeepBoundaryRows = 17
)

// skipDirs are directories the walk never descends into. None of them can
// contain a platform/ee twin, and walking them is slow.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	"dist": true, "build": true, ".next": true,
}

// FindRepoRoot walks up from dir until it finds the ancestor holding
// platform/go.mod, which is the repository root in both the enterprise repo
// and the community mirror.
func FindRepoRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(abs, "platform", "go.mod")); err == nil {
			return abs, nil
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", fmt.Errorf("no ancestor of %s contains platform/go.mod", dir)
		}
		abs = parent
	}
}

// HasEETree reports whether the enterprise tree is present. It is absent on
// the community mirror, which strips ee/ wholesale — so a guard that asserts
// on ee/ files must first ask this, and must say what it could not check
// rather than passing quietly.
func HasEETree(root string) bool {
	fi, err := os.Stat(filepath.Join(root, "ee", "platform"))
	return err == nil && fi.IsDir()
}

// IsCommunityMirror derives, from what the CHECKED-OUT TREE CONTAINS, whether
// this is the community mirror: lint.yml present and sync-community-repo.yml
// absent. That is the same marker scripts/lint-trap-handlers-exit.sh and
// suite_gate_floor_is_edition_aware_test.sh use.
//
// It is derived rather than flagged deliberately. A flag is a claim the caller
// makes; this is an observable outcome of the sync, and a guard that decides
// which tree it is on from anything the caller controls can be told to skip on
// the tree it was written for.
func IsCommunityMirror(root string) bool {
	_, lintErr := os.Stat(filepath.Join(root, ".github", "workflows", "lint.yml"))
	_, syncErr := os.Stat(filepath.Join(root, ".github", "workflows", "sync-community-repo.yml"))
	return lintErr == nil && os.IsNotExist(syncErr)
}

// DiscoverTwins returns every repo-relative platform path that also exists
// under ee/, sorted. This is the tree's own answer, derived on every run —
// never read from the census, so a pair added tomorrow shows up as unlisted
// rather than being invisible.
func DiscoverTwins(root string) ([]string, error) {
	eeRoot := filepath.Join(root, "ee", "platform")
	if !HasEETree(root) {
		return nil, nil
	}
	var out []string
	err := filepath.WalkDir(eeRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(filepath.Join(root, "ee"), path)
		if err != nil {
			return err
		}
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// Classify reads both copies of a pair and returns its population and the two
// deltas.
func Classify(root, platformRel string) (Population, int, int, error) {
	pBytes, err := os.ReadFile(filepath.Join(root, platformRel))
	if err != nil {
		return "", 0, 0, err
	}
	eBytes, err := os.ReadFile(filepath.Join(root, "ee", platformRel))
	if err != nil {
		return "", 0, 0, err
	}

	lineDelta := diffLineCount(splitLines(pBytes), splitLines(eBytes))

	codeDelta := -1
	if strings.HasSuffix(platformRel, ".go") {
		pCode, pErr := stripCommentsAndFormat(pBytes)
		eCode, eErr := stripCommentsAndFormat(eBytes)
		if pErr == nil && eErr == nil {
			codeDelta = diffLineCount(nonBlank(splitLines(pCode)), nonBlank(splitLines(eCode)))
		}
	}

	switch {
	case bytes.Equal(pBytes, eBytes):
		return PopulationIdentical, lineDelta, codeDelta, nil
	case bytes.Equal(stripBuildConstraints(pBytes), stripBuildConstraints(eBytes)) &&
		bothCopiesReachTheEnterpriseBuild(pBytes, eBytes):
		return PopulationBuildTagOnly, lineDelta, codeDelta, nil
	default:
		return PopulationDiverged, lineDelta, codeDelta, nil
	}
}

// negatedEnterpriseRE matches a constraint that EXCLUDES the enterprise build.
var negatedEnterpriseRE = regexp.MustCompile(`(?m)^//go:build .*!enterprise|^// \+build .*!enterprise`)

// bothCopiesReachTheEnterpriseBuild reports whether BOTH copies of a pair are
// actually compiled into the enterprise image.
//
// WHY THIS GUARDS THE POPULATION-2 TEST. stripBuildConstraints deletes every
// constraint line without reading it, so on its own it would call a pair
// "same source modulo a build tag" when the platform copy says `!enterprise`
// and the ee copy says `enterprise` — two files with identical bodies that
// are compiled in OPPOSITE editions. The recorded remedy for a keep-twin row
// is "collapse it once the package is de-forked", and collapsing that pair
// would delete the code from the enterprise binary: the surviving platform
// copy is excluded by its own constraint under -tags enterprise.
//
// This is the same lesson license_pair_byte_identity_test.sh records from
// #3759 R3 round 1, reached from the other direction. Such a pair is
// classified PopulationDiverged, which is a keep row and is never collapsed.
//
// BOTH copies are tested, not just the platform one. The first version of this
// checked the platform side alone, which is the side the prior art was NOT
// about: license_pair_byte_identity_test.sh asserts the constraint on the EE
// copy. A pair whose ee copy says `!enterprise` is equally mis-collapsible —
// the ee file is excluded from the overlaid build, so "the two copies are the
// same source" is again true of text and false of what compiles.
func bothCopiesReachTheEnterpriseBuild(platformSrc, eeSrc []byte) bool {
	return !negatedEnterpriseRE.Match(platformSrc) && !negatedEnterpriseRE.Match(eeSrc)
}

// stripBuildConstraints removes every //go:build / // +build line AND every
// blank line, so two copies that differ only by constructs which cannot change
// behaviour compare equal.
//
// Dropping the blank lines rather than the one blank that must follow a
// constraint is deliberate. The constraint's mandatory trailing blank is not
// the only whitespace the two copies disagree about — platform's
// agent/hitl/doc.go carries a stray extra blank 84 lines below its constraint —
// and a stray blank line is not a divergence anyone should have to reason
// about. Comments are NOT stripped here: prose drift is content, it is worth
// seeing, and it is what the code_delta column exists to tell apart.
func stripBuildConstraints(src []byte) []byte {
	lines := splitLines(src)
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "//go:build ") || strings.HasPrefix(t, "// +build ") {
			continue
		}
		out = append(out, l)
	}
	return []byte(strings.Join(out, "\n"))
}

// stripCommentsAndFormat re-prints a Go file from its AST with comments
// dropped, so two copies that differ only in prose compare equal. This is the
// axis that separates "someone improved a comment on one side" from "the two
// implementations do different things" — the census reports both, because
// they call for different follow-ups.
func stripCommentsAndFormat(src []byte) ([]byte, error) {
	fset := token.NewFileSet()
	// Parsing WITHOUT parser.ParseComments drops every comment, including the
	// build constraint, which is what we want here.
	file, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		return nil, err
	}
	ast.SortImports(fset, file)
	var buf bytes.Buffer
	if err := (&printer.Config{Mode: printer.TabIndent, Tabwidth: 8}).Fprint(&buf, fset, file); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// nonBlank drops blank lines. The AST printer preserves blank lines inside
// function bodies, and a blank line is not code: without this,
// agent/node_enforcement/monitor.go reads as 2 lines of code divergence when
// its two copies are in fact code-identical and differ only in prose.
func nonBlank(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func splitLines(b []byte) []string {
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// diffLineCount returns the number of lines `diff a b` would mark with < or >,
// i.e. len(a)+len(b)-2*LCS(a,b). Files here are at most a few thousand lines,
// so the quadratic table is not worth avoiding.
func diffLineCount(a, b []string) int {
	n, m := len(a), len(b)
	if n == 0 || m == 0 {
		return n + m
	}
	prev := make([]int, m+1)
	cur := make([]int, m+1)
	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if a[i-1] == b[j-1] {
				cur[j] = prev[j-1] + 1
			} else if prev[j] >= cur[j-1] {
				cur[j] = prev[j]
			} else {
				cur[j] = cur[j-1]
			}
		}
		prev, cur = cur, prev
	}
	return n + m - 2*prev[m]
}

// LoadCensus parses twin_census.tsv.
func LoadCensus(root string) ([]Row, error) {
	raw, err := os.ReadFile(filepath.Join(root, CensusPath))
	if err != nil {
		return nil, err
	}
	lines := splitLines(raw)
	if len(lines) == 0 {
		return nil, fmt.Errorf("%s is empty", CensusPath)
	}
	if lines[0] != censusHeader {
		return nil, fmt.Errorf("%s header is %q, want %q", CensusPath, lines[0], censusHeader)
	}
	var rows []Row
	for i, l := range lines[1:] {
		if strings.TrimSpace(l) == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "\t")
		if len(f) != 6 {
			return nil, fmt.Errorf("%s line %d has %d fields, want 6: %q", CensusPath, i+2, len(f), l)
		}
		var lineDelta, codeDelta int
		if _, err := fmt.Sscanf(f[2], "%d", &lineDelta); err != nil {
			return nil, fmt.Errorf("%s line %d: line_delta %q is not a number", CensusPath, i+2, f[2])
		}
		if _, err := fmt.Sscanf(f[3], "%d", &codeDelta); err != nil {
			return nil, fmt.Errorf("%s line %d: code_delta %q is not a number", CensusPath, i+2, f[3])
		}
		rows = append(rows, Row{
			PlatformPath: f[0],
			Population:   Population(f[1]),
			LineDelta:    lineDelta,
			CodeDelta:    codeDelta,
			Disposition:  Disposition(f[4]),
			Reason:       f[5],
		})
	}
	return rows, nil
}

// RenderCensus renders rows back to TSV, sorted by path so the file has one
// canonical form and a regeneration produces no spurious diff.
func RenderCensus(rows []Row) []byte {
	sorted := make([]Row, len(rows))
	copy(sorted, rows)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PlatformPath < sorted[j].PlatformPath })
	var b strings.Builder
	b.WriteString(censusHeader)
	b.WriteString("\n")
	for _, r := range sorted {
		fmt.Fprintf(&b, "%s\t%s\t%d\t%d\t%s\t%s\n",
			r.PlatformPath, r.Population, r.LineDelta, r.CodeDelta, r.Disposition, r.Reason)
	}
	return []byte(b.String())
}
