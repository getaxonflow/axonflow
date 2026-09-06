// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// writeTree writes a synthetic repository and returns its root.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestTheExtractorFindsEveryRegistrationShape is the anti-narrowness control.
//
// A census is bounded by the shape its author searched for, and the author is
// always the person who just decided what the shape is — so the shapes below
// are not the ones this scanner was written against. They are the shapes a
// reviewer PLANTED, several of which are not in the tree at all, because a
// scanner that only handles what exists today silently misses the next one.
//
// It started at three and is now five. Every addition came from someone else
// naming a shape I had not thought of, and three of the five were live defects
// the moment they were first planted. That ratio is the argument for the test.
//
// The tree's own worst case is here too and it is not hypothetical: nineteen
// registrations on main name a constant rather than a literal, two of them the
// platform's most-called governance routes.
func TestTheExtractorFindsEveryRegistrationShape(t *testing.T) {
	root := writeTree(t, map[string]string{
		"pkg/paths/paths.go": `package paths

const Exported = "/api/v1/from-another-package"
`,
		"svc/consts.go": `package svc

const localConst = "/api/v1/from-a-local-const"

var (
	varBlockPath = "/api/v1/from-a-var-block"
)
`,
		"svc/register.go": `package svc

import (
	"net/http"

	"example/pkg/paths"

	"github.com/gorilla/mux"
)

type row struct {
	suffix  string
	handler http.HandlerFunc
}

type cfg struct{ base string }

func Register(r *mux.Router, h http.HandlerFunc, table []row) {
	r.HandleFunc("/api/v1/plain-literal", h)
	r.Handle(localConst, h)
	r.HandleFunc(paths.Exported, h)
	r.HandleFunc(varBlockPath, h)
	r.HandleFunc("/api/v1/con"+"catenated", h)
	r.PathPrefix("/api/v1/prefixed").HandlerFunc(h)

	sub := r.PathPrefix("/api/v1/parent").Subrouter()
	sub.HandleFunc("/child", h)

	// The same, behind a var declaration and behind an immediate chain. A
	// learner keyed on := alone reports both children as top-level routes.
	var sub2 = r.PathPrefix("/api/v1/parent2").Subrouter()
	sub2.HandleFunc("/child2", h)
	r.PathPrefix("/api/v1/parent3").Subrouter().HandleFunc("/chained", h)

	abs := r.NewRoute().Subrouter()
	abs.HandleFunc("/api/v1/through-a-bare-subrouter", h)

	for _, row := range table {
		r.HandleFunc(row.suffix, row.handler)
	}
}
`,
		"svc/register_test.go": `package svc

func TestIgnored() {
	// A route registered in a _test.go file is not a route the server serves.
	// r.HandleFunc("/api/v1/only-in-a-test", nil)
}
`,
		"svc/enterprise_only.go": `//go:build enterprise

package svc

import "github.com/gorilla/mux"

func RegisterEnterprise(r *mux.Router) {
	r.HandleFunc("/api/v1/enterprise-only", nil)
}
`,
	})

	d, err := Derive(root, []string{"pkg", "svc"})
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if d.FilesParsed == 0 {
		t.Fatal("the walk parsed nothing, so every assertion below is about an empty scan")
	}

	want := []string{
		"/api/v1/concatenated",
		"/api/v1/enterprise-only",
		"/api/v1/from-a-local-const",
		"/api/v1/from-a-var-block",
		"/api/v1/from-another-package",
		// The subrouter's OWN prefix is a route in its own right: PathPrefix is
		// a claim on a region of the URL space whether or not a handler hangs
		// directly off it, and a registry that did not have to cover it would
		// let a whole subtree in unexamined.
		"/api/v1/parent",
		"/api/v1/parent/child",
		"/api/v1/parent2",
		"/api/v1/parent2/child2",
		"/api/v1/parent3",
		"/api/v1/parent3/chained",
		"/api/v1/plain-literal",
		"/api/v1/prefixed",
		"/api/v1/through-a-bare-subrouter",
	}
	got := d.Patterns()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the extractor found\n  %s\nwant\n  %s",
			strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}

	// The unresolvable table-driven registration must be REPORTED, not dropped.
	// A scanner that silently skips what it cannot read reports full coverage
	// of a route set it never saw.
	un := d.Unresolved()
	if len(un) != 1 {
		t.Fatalf("expected exactly one unresolved site, got %d: %+v", len(un), un)
	}
	if !strings.Contains(un[0].Expr, "row.suffix") {
		t.Errorf("the unresolved site does not name the expression a reviewer has to look "+
			"at: %q", un[0].Expr)
	}

	// The enterprise-tagged file must be classified as such, or the census
	// cannot tell a capability the mirror keeps from one it strips.
	var sawEnterprise bool
	for _, s := range d.Routes {
		if s.Pattern == "/api/v1/enterprise-only" {
			sawEnterprise = true
			if s.Edition != "enterprise" {
				t.Errorf("a //go:build enterprise file was classified %q", s.Edition)
			}
		}
	}
	if !sawEnterprise {
		t.Error("the enterprise-only route was not found at all")
	}
	if len(d.EnterpriseDirs) != 1 || d.EnterpriseDirs[0] != "svc" {
		t.Errorf("EnterpriseDirs = %v, want [svc]", d.EnterpriseDirs)
	}
}

// TestAnUnresolvableSubrouterPrefixPoisonsItsChildren is the trap a confident
// scanner falls into.
//
// If the PREFIX cannot be read but the SUFFIX can, concatenating them yields a
// path the server does not serve — and a registry entry can then be written to
// match it, so the coverage check passes while the real route is uncovered. An
// admitted unknown is strictly better than a confident wrong answer.
func TestAnUnresolvableSubrouterPrefixPoisonsItsChildren(t *testing.T) {
	root := writeTree(t, map[string]string{
		"svc/register.go": `package svc

import (
	"net/http"

	"github.com/gorilla/mux"
)

type cfg struct{ base string }

func Register(r *mux.Router, c cfg, h http.HandlerFunc) {
	sub := r.PathPrefix(c.base).Subrouter()
	sub.HandleFunc("/leaf", h)
	// The same shape behind a var declaration, which a learner keyed on :=
	// does not see and which therefore yields a confident /also-leaf.
	var sub2 = r.PathPrefix(c.base).Subrouter()
	sub2.HandleFunc("/also-leaf", h)
}
`,
	})
	d, err := Derive(root, []string{"svc"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range d.Patterns() {
		if p == "/leaf" || p == "/also-leaf" {
			t.Fatalf("the scanner reported %s as a top-level route; the prefix it hangs "+
				"off was never resolved, so that path is invented", p)
		}
	}

	// THE CHILD'S OWN SITE must be reported, named by its own expression.
	//
	// The first version of this test asserted only `len(Unresolved()) != 0`,
	// and master killed it: deleting the poison block entirely left the whole
	// package green, because the PathPrefix(c.base) call is ITSELF an
	// unresolved site and satisfied the count. The child went from reported to
	// silently dropped and nothing noticed. So each site is now identified by
	// the expression a reviewer would have to read, and the count is EXACT — at
	// least-one would be satisfied by the parent again.
	want := map[string]bool{
		"PathPrefix(c.base)":                                  false, // the parent, twice
		"HandleFunc(" + unknownPrefixNote + "\"/leaf\")":      false,
		"HandleFunc(" + unknownPrefixNote + "\"/also-leaf\")": false,
	}
	var parents int
	for _, site := range d.Unresolved() {
		key := site.Method + "(" + site.Expr + ")"
		if key == "PathPrefix(c.base)" {
			parents++
			want[key] = true
			continue
		}
		if _, ok := want[key]; ok {
			want[key] = true
			continue
		}
		t.Errorf("an unexpected unresolved site: %s", site.SiteKey())
	}
	for key, seen := range want {
		if !seen {
			t.Errorf("the unresolved site %s was not reported. A child whose prefix could "+
				"not be read must be REPORTED, not dropped: dropping it is the silent hole "+
				"the whole derivation exists to avoid", key)
		}
	}
	if parents != 2 {
		t.Errorf("expected both PathPrefix(c.base) calls to be reported, got %d", parents)
	}
	if got := len(d.Unresolved()); got != 4 {
		t.Errorf("expected exactly 4 unresolved sites (two parents, two poisoned children), "+
			"got %d: %+v", got, d.Unresolved())
	}
}

// TestAnAmbiguousCrossPackageConstantDoesNotResolve covers the case where two
// packages of the same name declare the same identifier with different values.
// Resolving it to whichever the walk reached last would produce a confident
// wrong path in exactly the way the test above rejects.
func TestAnAmbiguousCrossPackageConstantDoesNotResolve(t *testing.T) {
	root := writeTree(t, map[string]string{
		"a/paths/paths.go": "package paths\n\nconst P = \"/api/v1/one\"\n",
		"b/paths/paths.go": "package paths\n\nconst P = \"/api/v1/two\"\n",
		"svc/register.go": `package svc

import (
	"net/http"

	"example/a/paths"

	"github.com/gorilla/mux"
)

func Register(r *mux.Router, h http.HandlerFunc) {
	r.HandleFunc(paths.P, h)
}
`,
	})
	d, err := Derive(root, []string{"a", "b", "svc"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range d.Patterns() {
		if p == "/api/v1/one" || p == "/api/v1/two" {
			t.Fatalf("the scanner picked %q out of two same-named packages declaring "+
				"different values for the same identifier", p)
		}
	}
	if len(d.Unresolved()) != 1 {
		t.Fatalf("the ambiguous registration was not reported: %+v", d.Unresolved())
	}
}

// TestSourceEditionKnowsAllThreeStrippingMechanisms pins the classifier against
// the community sync's actual rules. Knowing only some of them reports a
// stripped file as a deleted one.
func TestSourceEditionKnowsAllThreeStrippingMechanisms(t *testing.T) {
	root := writeTree(t, map[string]string{
		"ee/platform/x.go":               "package x\n",
		"platform/a/plain_enterprise.go": "package a\n",
		"platform/a/tagged.go":           "//go:build enterprise\n\npackage a\n",
		"platform/a/legacy_tagged.go":    "// +build enterprise\n\npackage a\n",
		"platform/a/negated.go":          "//go:build !enterprise\n\npackage a\n",
		"platform/a/mentions.go":         "package a\n\n// A comment mentioning //go:build enterprise is not a constraint.\n",
		"platform/a/community.go":        "package a\n",
	})
	for rel, want := range map[string]string{
		"ee/platform/x.go":               "enterprise",
		"platform/a/plain_enterprise.go": "enterprise",
		"platform/a/tagged.go":           "enterprise",
		"platform/a/legacy_tagged.go":    "enterprise",
		"platform/a/negated.go":          "community",
		"platform/a/community.go":        "community",
	} {
		got, err := SourceEdition(root, rel)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if got != want {
			t.Errorf("SourceEdition(%s) = %q, want %q", rel, got, want)
		}
	}
	// The one that is easy to get wrong in the other direction: a file that
	// merely MENTIONS the directive in prose is not enterprise-only. The
	// expression is line-anchored, and the anchor is the whole reason.
	got, err := SourceEdition(root, "platform/a/mentions.go")
	if err != nil {
		t.Fatal(err)
	}
	if got != "community" {
		t.Errorf("a file mentioning the directive in a comment was classified %q; the "+
			"line anchor in the sync's expression is what stops that", got)
	}
}

// ---------------------------------------------------------------- the tree
//
// Everything above runs on synthetic source. Everything below runs on this
// repository, which is where the census's claims actually have to hold.

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func deriveRepo(t *testing.T) (*Derivation, *Registry) {
	t.Helper()
	reg := Load()
	d, err := Derive(repoRoot(t), reg.ScanRoots)
	if err != nil {
		t.Fatalf("deriving from the tree: %v", err)
	}
	return d, reg
}

// TestTheTreeDerivationIsNotVacuous is the positive control that every count
// this package publishes rests on.
//
// A zero from a scan is indistinguishable from a zero from a broken scan, and
// the coverage check below PASSES on an empty inventory. So the derivation has
// to prove it found things it must find before anything is concluded from what
// it did not find.
//
// The floors are MEASURED, not guessed, and they differ by tree because the
// trees differ: on 2026-09-04, rebased onto ca9fccefd, the enterprise
// repository derived 737 files / 284 routes / 413 sites / 48 enterprise-tagged
// directories, and the staged community mirror derived 473 / 175 / 233 / 0.
//
// THE FILE COUNT MOVES WITH EVERY MERGE INTO MAIN and this one has already
// moved twice (735 -> 737 when #3707 landed two files). It is quoted because
// the floors below are on files and routes, and a floor with no measurement
// beside it is a guess — but the AUTHORITY is the line this test prints live
// on every run in both lanes, not this comment. A drifted file count here is
// expected drift; a drifted ROUTE count is a finding, because routes move only
// when the scanner's decisions do.
//
// Routes moved once, with round 8's inversion: three left the enterprise set
// and three the mirror's, each a registration on a router assigned inside a
// function body, and each now carrying a route_exemption. The mirror is smaller for a
// reason — the sync strips ee/ and the enterprise half of every build-tag pair
// — so a single floor would either be vacuous in one tree or red in the other.
// Each floor sits below its measurement with room for ordinary growth and far
// above what a walk that had stopped working would produce.
func TestTheTreeDerivationIsNotVacuous(t *testing.T) {
	d, _ := deriveRepo(t)
	mirror := TreeIsCommunityMirror(repoRoot(t))

	// The evidence line. These numbers are NOT frozen into the census: they
	// move whenever any Go file is added, so a document carrying them would go
	// stale on unrelated work and be regenerated without being read. Printing
	// them on every run in both lanes keeps them fresh and attributable to a
	// specific commit.
	tree := "enterprise repository"
	if mirror {
		tree = "community mirror"
	}
	t.Logf("DERIVATION (%s): files=%d dirs=%d sites=%d routes=%d unresolved=%d "+
		"enterprise-dirs=%d", tree, d.FilesParsed, d.DirsWalked, len(d.Routes),
		len(d.Patterns()), len(d.Unresolved()), len(d.EnterpriseDirs))

	// The numeric floors are a SECOND line, and R3 measured how weak a line:
	// with constant resolution entirely broken the derivation still produced
	// 281 routes against a floor of 250, so the floor alone would have passed a
	// scanner that had stopped following constants. What actually carries this
	// test is the four named controls below, none of which is registered with a
	// string literal. The floors are kept for the case the controls cannot
	// speak to - a walk that reached almost nothing - and are stated here as
	// the weaker check rather than left to look like the strong one.
	minFiles, minRoutes := 600, 250
	if mirror {
		minFiles, minRoutes = 400, 150
	}
	if d.FilesParsed < minFiles {
		t.Fatalf("the walk parsed %d files (floor %d for this tree); the scan roots hold "+
			"hundreds, so the walk is not reaching them", d.FilesParsed, minFiles)
	}
	if len(d.Patterns()) < minRoutes {
		t.Fatalf("the walk resolved %d routes (floor %d for this tree); that is far below "+
			"the platform's real surface", len(d.Patterns()), minRoutes)
	}

	found := map[string]bool{}
	for _, p := range d.Patterns() {
		found[p] = true
	}
	// Controls that hold in BOTH trees, each aimed at a different resolution
	// mechanism, and every one of them registered WITHOUT a string literal:
	//
	//   /api/v1/decide             r.Handle(decisionHandlerPath, ...)   package-local const
	//   /api/v1/access/evaluation  r.Handle(authzenHandlerPath, ...)    package-local const
	//   /api/v1/system-policies    PathPrefix(policypath.SystemPolicies) cross-package const
	//   /v1/logs                   sub.HandleFunc(coworkOTELLogsPath)   const on a subrouter
	//
	// A scanner that greps for `"/api/v1` finds NONE of them, and would report
	// a clean sweep of a route set missing the platform's two most-called
	// governance surfaces. If any of these disappears from the derivation, the
	// mechanism it stands for has broken and no count here can be trusted.
	for _, control := range []string{
		"/api/v1/decide",
		"/api/v1/access/evaluation",
		"/api/v1/system-policies",
		"/v1/logs",
	} {
		if !found[control] {
			t.Fatalf("the derivation did not find %s, which is registered through a "+
				"CONSTANT. Constant resolution is broken and no count from this scan "+
				"can be trusted", control)
		}
	}

	if mirror {
		// The mirror's own positive statement, in the other direction: the
		// sync must have stripped every enterprise-tagged file, so a
		// classifier walking the published tree must find NO enterprise
		// directory at all. A non-zero here is a leak.
		if len(d.EnterpriseDirs) != 0 {
			t.Fatalf("this is a community mirror and the derivation found %d "+
				"enterprise-tagged director(ies): %v", len(d.EnterpriseDirs), d.EnterpriseDirs)
		}
		return
	}

	// Enterprise-tree-only controls. Both subjects are enterprise-tagged, so
	// asserting them on the mirror would assert the sync had failed.
	if !found["/api/v1/circuit-breaker/trip"] {
		t.Fatal("the derivation did not find /api/v1/circuit-breaker/trip, which is " +
			"registered as \"/trip\" on a PathPrefix subrouter; prefix composition is broken")
	}
	if len(d.EnterpriseDirs) < 20 {
		t.Fatalf("the derivation found %d enterprise-tagged directories; the tree has "+
			"dozens", len(d.EnterpriseDirs))
	}
}

// TestEveryRegisteredRouteHasACapabilityEntry is #3590's fifth failure class
// and the reason this registry cannot go stale the way the /health list did.
//
// The candidate set is DERIVED from the source, so a new route arrives in it
// the moment it is registered, whether or not anybody remembered the registry.
// The default is inclusion: an uncovered route fails, and the only way out is a
// route_exemption carrying a reason.
func TestEveryRegisteredRouteHasACapabilityEntry(t *testing.T) {
	d, reg := deriveRepo(t)
	exempt := map[string]bool{}
	for _, x := range reg.RouteExemptions {
		exempt[x.Pattern] = true
	}
	var uncovered []string
	for _, route := range d.Patterns() {
		if exempt[route] {
			continue
		}
		if reg.CapabilityForRoute(route) == nil {
			uncovered = append(uncovered, route)
		}
	}
	sort.Strings(uncovered)
	if len(uncovered) > 0 {
		t.Fatalf("%d registered route(s) belong to no capability:\n  %s\n\n"+
			"Every route the platform serves is part of some capability. Add it to the "+
			"registry entry that owns it, or add a route_exemption with a reason.",
			len(uncovered), strings.Join(uncovered, "\n  "))
	}
}

// TestEveryUnresolvedSiteIsExempted holds the other half of the derivation: a
// call site the scanner could not read is a declared, reviewed hole with an
// owner, never a silent one.
func TestEveryUnresolvedSiteIsExempted(t *testing.T) {
	d, reg := deriveRepo(t)
	exempt := map[string]string{}
	for _, x := range reg.RouteExemptions {
		exempt[x.Pattern] = x.Reason
	}
	var unexplained []string
	for _, s := range d.Unresolved() {
		key := s.SiteKey()
		if _, ok := exempt[key]; !ok {
			unexplained = append(unexplained, key)
		}
	}
	sort.Strings(unexplained)
	if len(unexplained) > 0 {
		t.Fatalf("%d route-registration site(s) the scanner could not resolve, and which "+
			"no route_exemption explains:\n  %s\n\n"+
			"Either the argument can be made resolvable, or add a route_exemption naming "+
			"this exact key and saying why the URL space is still covered.",
			len(unexplained), strings.Join(unexplained, "\n  "))
	}
}

// TestEveryExemptionIsCoveredByACapabilityRegisteredInTheSameFile is the
// FILE-scoped half of the exemption citation rule, and it exists for the one
// row the path-scoped half cannot reach.
//
// Rule 2 in registry.go asks: does a capability the reason names claim the
// path in the exemption key? On a key with no literal path — a struct-field
// argument like `rt.suffix` — there is no path to ask about, and rule 3 can
// only insist that SOME real capability is named. A row citing one real id
// beside an invented one satisfies that and still asserts a coverage nobody
// checked.
//
// The derivation supplies what the registry alone cannot: which FILE each
// route was registered in. A capability that covers an unattributed site in
// `static_policy_api_handlers.go` must claim at least one route the scanner
// found in that same file. That is the pathless analogue of rule 2, and it is
// only expressible here, where the derivation is in hand.
func TestEveryExemptionIsCoveredByACapabilityRegisteredInTheSameFile(t *testing.T) {
	d, reg := deriveRepo(t)

	// route pattern -> the files it is registered in.
	fileOf := map[string]map[string]bool{}
	for _, s := range d.Routes {
		if !s.Resolved || s.Pattern == "" {
			continue
		}
		if fileOf[s.Pattern] == nil {
			fileOf[s.Pattern] = map[string]bool{}
		}
		fileOf[s.Pattern][s.File] = true
	}
	// The control: the derivation must actually have attributed routes to
	// files, or every case below passes on an empty map.
	//
	// TREE-AWARE, like every other floor in this file. The first version used
	// one number taken from the enterprise tree (200) and red the community
	// mirror, which derives 175 routes because the sync strips ee/ and the
	// enterprise half of every build-tag pair. A floor derived from one tree
	// and applied to both is not a measurement of either.
	floor := 250
	if TreeIsCommunityMirror(repoRoot(t)) {
		floor = 150
	}
	if len(fileOf) < floor {
		t.Fatalf("control: only %d routes carry a file attribution (floor %d for this "+
			"tree); the check below would be about almost nothing", len(fileOf), floor)
	}

	byID := map[string]*Entry{}
	for i := range reg.Entries {
		byID[reg.Entries[i].ID] = &reg.Entries[i]
	}

	// PATHLESS ROWS ONLY, and the scoping is the rule rather than a way to
	// make it pass.
	//
	// A row whose key carries a literal path is already tied to that EXACT
	// path by rule 2 in registry.go, which is strictly stronger than a file.
	// Applying the file rule to those rows would also be wrong on its face:
	// the seven `run.go` rows exist precisely because the agent's own
	// registration became unattributed, and their coverage comes from the
	// capability entry whose other registration is on the orchestrator. A
	// capability legitimately claims a path this file no longer contributes.
	//
	// The pathless row has no path to match, so the file is the only handle
	// left, and it is a real one.
	var checked, skipped int
	for _, x := range reg.RouteExemptions {
		if quotedPathInPattern.MatchString(x.Pattern) {
			skipped++
			continue
		}
		file, _, found := strings.Cut(x.Pattern, ":")
		if !found {
			t.Errorf("exemption key %q has no file prefix", x.Pattern)
			continue
		}
		var named []*Entry
		for _, tok := range regexp.MustCompile(`\b[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\b`).
			FindAllString(x.Reason, -1) {
			if e, ok := byID[tok]; ok {
				named = append(named, e)
			}
		}
		var covers bool
		for _, e := range named {
			for _, rt := range e.Routes {
				if fileOf[rt][file] {
					covers = true
				}
			}
		}
		checked++
		if !covers {
			ids := make([]string, 0, len(named))
			for _, e := range named {
				ids = append(ids, e.ID)
			}
			t.Errorf("exemption %q names %v, and none of them claims a route this scanner "+
				"found registered in %s. An exemption asserts that some capability covers "+
				"the surface at this site; a capability whose routes are all in other "+
				"files is not that capability", x.Pattern, ids, file)
		}
	}
	// The floor, so this test cannot quietly become about nothing: at least
	// one pathless row must exist and have been checked, and every row must
	// have been either checked here or covered by rule 2 there.
	if checked == 0 {
		t.Errorf("no pathless exemption was checked. If the last one has gone, delete this " +
			"test with it rather than leaving a green check over an empty set; if one " +
			"exists, the skip condition has stopped recognising it")
	}
	if checked+skipped != len(reg.RouteExemptions) {
		t.Errorf("checked %d + skipped %d != %d exemptions; a row in neither bucket is an "+
			"unchecked coverage claim", checked, skipped, len(reg.RouteExemptions))
	}
}

// TestNoRouteExemptionIsStale is the other direction. An exemption whose
// subject has gone is a licence with nothing under it, and the next reader
// reads it as a live carve-out.
func TestNoRouteExemptionIsStale(t *testing.T) {
	d, reg := deriveRepo(t)
	live := map[string]bool{}
	for _, p := range d.Patterns() {
		live[p] = true
	}
	for _, s := range d.Unresolved() {
		live[s.SiteKey()] = true
	}
	for _, x := range reg.RouteExemptions {
		if !live[x.Pattern] {
			t.Errorf("route_exemption %q matches nothing the derivation finds; it is "+
				"stale and should be deleted", x.Pattern)
		}
	}
}

// TestEveryEnterpriseImplementationEntryNamesEnterpriseSource checks the
// classification against the build constraints, in the direction that matters:
// a capability the registry says is Enterprise-only must have source the mirror
// actually strips.
func TestEveryEnterpriseImplementationEntryNamesEnterpriseSource(t *testing.T) {
	root := repoRoot(t)
	if TreeIsCommunityMirror(root) {
		t.Skip("community mirror: the enterprise source this test inspects is stripped here " +
			"by construction, which is the property being relied on rather than tested")
	}
	var checked int
	for _, e := range Load().Entries {
		if e.Classification != ClassEnterpriseImplementation {
			continue
		}
		var enterprise int
		for _, impl := range e.Implementation {
			files, err := goFilesUnder(root, impl)
			if err != nil {
				t.Errorf("%s: %v", e.ID, err)
				continue
			}
			for _, f := range files {
				ed, err := SourceEdition(root, f)
				if err != nil {
					t.Errorf("%s: %v", e.ID, err)
					continue
				}
				if ed == "enterprise" {
					enterprise++
				}
			}
		}
		checked++
		if enterprise == 0 {
			t.Errorf("%s is classified %q but none of its implementation files is "+
				"enterprise-only by the sync's own rule. Either the classification is "+
				"aspirational or the source leaks to the mirror",
				e.ID, ClassEnterpriseImplementation)
		}
	}
	if checked == 0 {
		t.Fatal("no entry is classified enterprise_implementation, so this test asserted " +
			"nothing")
	}
}

// TestThreeShapesAReviewerWouldPlant covers the registration shapes that a
// hostile reviewer reaches for, and states which answer is CORRECT for each.
// Two of the three are correct as a resolved path; the third is correct as a
// REPORTED UNKNOWN, and the difference matters more than it looks.
//
// A silent drop is the failure. A poisoned report is not: it forces a declared
// route_exemption with a reason and a reviewer's eyes, which is exactly what
// should happen to a call site nobody can read statically.
func TestPlantedRegistrationShapes(t *testing.T) {
	root := writeTree(t, map[string]string{
		"pkg/paths/paths.go": `package paths

const Base = "/api/v1"
const Leaf = "/from-two-constants"

// A constant defined in TERMS OF ANOTHER CONSTANT, and a second level of it.
// This is the shape that made the const collection a fixpoint: resolving as the
// walk went would depend on file order and would silently fail to follow the
// chain, leaving a perfectly resolvable route reported as unknown.
const Mid = Base + "/mid"
const Deep = Mid + "/deep"
`,
		"svc/register.go": `package svc

import (
	"net/http"

	"example/pkg/paths"

	"github.com/gorilla/mux"
)

const localBase = "/api/v1"
const localMid = localBase + "/local-mid"
const localChained = localMid + "/chained"

// 1. A path assembled by CONCATENATING TWO CONSTANTS, neither a literal.
func RegisterConcatenated(r *mux.Router, h http.HandlerFunc) {
	r.HandleFunc(paths.Base+paths.Leaf, h)
	r.HandleFunc(localBase+"/local-plus-literal", h)
	// Three terms, which parse as (a+b)+c and so exercise the recursion twice.
	r.HandleFunc(paths.Base+"/three"+"/terms", h)
	// A chained constant, and a chain of chained constants, declared in a
	// DIFFERENT FILE from this one and resolved in the other direction to the
	// walk order.
	r.HandleFunc(paths.Deep, h)
	r.HandleFunc(localChained, h)
}

// 2. A route registered THROUGH A HELPER that takes the path as an argument.
// The registration the scanner can see names a PARAMETER, so the path is not
// statically knowable at that site at all.
func register(r *mux.Router, path string, h http.HandlerFunc) {
	r.HandleFunc(path, h)
}

func RegisterViaHelper(r *mux.Router, h http.HandlerFunc) {
	register(r, "/api/v1/through-a-helper", h)
}

// 4. A registration at PACKAGE level, inside no function body at all.
var packageLevelRouter = mux.NewRouter()

var _ = packageLevelRouter.HandleFunc("/api/v1/registered-at-package-level", nil)

func init() { packageLevelRouter.HandleFunc("/api/v1/in-init", nil) }

// 5. A PACKAGE-LEVEL SUBROUTER used inside a function. It is in scope in every
// function of the package, so a per-function map that starts empty records its
// children BARE.
var packageLevelSub = packageLevelRouter.PathPrefix("/api/v1/pkgsub").Subrouter()

func RegisterOnPackageSubrouter(h http.HandlerFunc) {
	packageLevelSub.HandleFunc("/from-function", h)
}

// ...and a function that BINDS that same name must not inherit the prefix,
// which is H2 one level up.
func ShadowsThePackageSubrouter(packageLevelSub *mux.Router, h http.HandlerFunc) {
	packageLevelSub.HandleFunc("/api/v1/from-a-shadowing-parameter", h)
}

// 6. THE ORIGINAL H2 SHAPE, kept permanently. One function's LOCAL subrouter
// variable and another function's PARAMETER of the same name. A file-scoped map
// lets the first rename the second: the live near-miss on main is
// customer-portal, which names a subrouter apiRouter and has three functions
// taking a parameter of that name.
func AlphaOwner(r *mux.Router, h http.HandlerFunc) {
	alpha := r.PathPrefix("/api/v1/alpha").Subrouter()
	alpha.HandleFunc("/one", h)
}

func AlphaBorrower(alpha *mux.Router, h http.HandlerFunc) {
	alpha.HandleFunc("/api/v1/beta", h)
}

// 7. CLOSURES. A func literal SEES the enclosing function's subrouter, so its
// registration carries the prefix — unless it binds the name itself, in which
// case it is talking about something else and must not inherit.
func Closures(r *mux.Router, h http.HandlerFunc) {
	outer := r.PathPrefix("/api/v1/outer").Subrouter()
	inherits := func() { outer.HandleFunc("/from-a-closure", h) }
	shadows := func(outer *mux.Router) { outer.HandleFunc("/api/v1/from-a-closure-param", h) }
	_, _ = inherits, shadows
}

// 8. NESTED SUBROUTERS. A subrouter hanging off another subrouter must carry
// BOTH prefixes, and an unreadable outer prefix must poison the inner one.
func Nested(r *mux.Router, c cfg, h http.HandlerFunc) {
	one := r.PathPrefix("/api/v1/one").Subrouter()
	two := one.PathPrefix("/two").Subrouter()
	two.HandleFunc("/three", h)

	badOuter := r.PathPrefix(c.base).Subrouter()
	badInner := badOuter.PathPrefix("/mid").Subrouter()
	badInner.HandleFunc("/deep", h)
}
`,
		"svc/enterprise_route.go": `//go:build enterprise

package svc

import "github.com/gorilla/mux"

func RegisterEnterpriseOnly(r *mux.Router) {
	r.HandleFunc("/api/v1/enterprise-literal", nil)
}
`,
	})

	d, err := Derive(root, []string{"pkg", "svc"})
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	found := map[string]bool{}
	for _, p := range d.Patterns() {
		found[p] = true
	}

	// 1. Both concatenations resolve. staticString folds a BinaryExpr by
	// recursing on each side, so a constant on either side is followed.
	for _, want := range []string{
		"/api/v1/from-two-constants",
		"/api/v1/local-plus-literal",
		"/api/v1/three/terms",
		"/api/v1/mid/deep",
		"/api/v1/local-mid/chained",
	} {
		if !found[want] {
			t.Errorf("a path concatenated from constants was not derived: %s", want)
		}
	}

	// 3. THE BUILD-TAG PLANT, and the reason it can never be missed: go/parser
	// does not evaluate build constraints, so Derive reads every file whatever
	// tags the caller was built with. The derivation therefore always sees the
	// ENTERPRISE SUPERSET — which is the only inventory a census can be built
	// on, because a derivation that read only the untagged tree would describe
	// a platform narrower than the one that ships. This package carries no
	// build constraint of its own, so this assertion runs identically under
	// `go test` and `go test -tags enterprise`.
	if !found["/api/v1/enterprise-literal"] {
		t.Error("a route behind //go:build enterprise was not derived; the derivation is " +
			"reading a narrower tree than the one that ships")
	}
	var taggedEdition string
	for _, s := range d.Routes {
		if s.Pattern == "/api/v1/enterprise-literal" {
			taggedEdition = s.Edition
		}
	}
	if taggedEdition != "enterprise" {
		t.Errorf("the enterprise-tagged route was classified %q", taggedEdition)
	}

	// A registration OUTSIDE any function body. Scoping the walk per function
	// is what fixed the parameter-shadow defect, and it silently dropped this
	// shape in the same move — a route reached by no body at all. A dropped
	// route is the one outcome the whole derivation exists to prevent, so the
	// fix that removed an invented path had, for one commit, created a missing
	// one.
	for _, want := range []string{"/api/v1/registered-at-package-level", "/api/v1/in-init"} {
		if !found[want] {
			t.Errorf("%s was not derived; the per-function walk reaches no body for a "+
				"package-level initialiser", want)
		}
	}

	// 5. A package-level subrouter is in scope in every function, so its
	// children must carry its prefix — and must NOT appear bare. The bare form
	// is an invented top-level route, and it is the exact inverse of the drop
	// the package-level pass fixes: the same scoping change produced both.
	if !found["/api/v1/pkgsub/from-function"] {
		t.Error("a registration on a PACKAGE-LEVEL subrouter did not carry its prefix; the " +
			"per-function map starts empty and treated it as an unknown receiver")
	}
	if found["/from-function"] {
		t.Error("a registration on a package-level subrouter was recorded BARE, which is a " +
			"top-level route the server does not serve")
	}
	// 6. The original H2 shape. `alpha` is a local subrouter in one function and
	// a PARAMETER in another; a file-scoped map lets the first rename the
	// second, which both invents a path and drops a real one.
	if !found["/api/v1/alpha/one"] {
		t.Error("the owning function's own subrouter registration was lost")
	}
	if !found["/api/v1/beta"] {
		t.Error("a route registered on a PARAMETER named like another function's subrouter " +
			"was dropped; the subrouter map is leaking across function boundaries")
	}
	if found["/api/v1/alpha/api/v1/beta"] {
		t.Error("one function's subrouter prefix was applied to another function's " +
			"parameter of the same name — a path no server serves")
	}

	// 7. Closures.
	if !found["/api/v1/outer/from-a-closure"] {
		t.Error("a closure did not inherit its enclosing function's subrouter prefix; a " +
			"func literal is not a fresh scope")
	}
	if found["/from-a-closure"] {
		t.Error("a closure's registration was recorded bare, losing the prefix it can see")
	}
	if found["/api/v1/outer/api/v1/from-a-closure-param"] {
		t.Error("a closure parameter shadowing the outer subrouter inherited its prefix")
	}

	// 8. Nested subrouters, both directions.
	if !found["/api/v1/one/two/three"] {
		t.Error("a subrouter hanging off another subrouter lost the outer prefix; the " +
			"poison and the composition both stop at one level without this")
	}
	if found["/two/three"] {
		t.Error("a nested subrouter's child was recorded with only the inner prefix — a " +
			"top-level route the server does not serve")
	}
	if found["/mid/deep"] || found["/deep"] {
		t.Error("an unreadable OUTER prefix did not poison the inner subrouter; the poison " +
			"stopped at one level")
	}

	// The shadowing case, and it must REPORT rather than assume.
	//
	// A parameter named like a known subrouter is not that subrouter, so it
	// must not inherit the prefix — H2 one level up. But falling back to NO
	// prefix is also an assumption, and here it is one we know better than: the
	// name meant a prefixed subrouter one scope out and now means something the
	// scanner cannot read. Every plain `r.HandleFunc(...)` relies on the
	// no-prefix assumption and must, because most routers are unprefixed; this
	// case is different precisely because we HAD the information and lost it.
	if found["/api/v1/pkgsub/api/v1/from-a-shadowing-parameter"] {
		t.Error("the package-level prefix was applied to a shadowing parameter's route")
	}
	if found["/api/v1/from-a-shadowing-parameter"] {
		t.Error("a route on a name that SHADOWS a known subrouter was resolved with no " +
			"prefix. That is an assumption, not a reading: the name meant a prefixed " +
			"subrouter one scope out. It must be reported")
	}
	var shadowReported bool
	for _, site := range d.Unresolved() {
		if strings.Contains(site.Expr, "from-a-shadowing-parameter") {
			shadowReported = true
			if !strings.Contains(site.Expr, unknownPrefixNote) {
				t.Errorf("the shadowed-subrouter site is reported without saying why: %q",
					site.Expr)
			}
		}
	}
	if !shadowReported {
		t.Error("a registration on a name shadowing a known subrouter was neither resolved " +
			"nor reported")
	}

	// 2. The helper. The path must NOT appear as a resolved route — the
	// scanner cannot see it, and inventing it would be a confident wrong
	// answer — and the call site must be REPORTED so it cannot be silently
	// dropped.
	if found["/api/v1/through-a-helper"] {
		t.Error("the scanner resolved a path it cannot see: the registration inside the " +
			"helper names a PARAMETER, so any path attributed to it is invented")
	}
	var reported bool
	for _, s := range d.Unresolved() {
		if strings.Contains(s.Expr, "path") && strings.HasSuffix(s.File, "svc/register.go") {
			reported = true
		}
	}
	if !reported {
		t.Errorf("the helper's registration was neither resolved nor reported. A silent "+
			"drop is the failure mode this whole derivation exists to avoid.\nunresolved: %+v",
			d.Unresolved())
	}
}

// TestAConstantChainTerminatesAndNeverInvents covers the two failures a
// fixpoint invites, both of which are worse than the problem it solves.
//
//  1. A CYCLE must terminate and resolve nothing. Go itself rejects a constant
//     initialisation cycle, so this cannot reach a build — but go/parser does
//     not type-check, and a scanner that hangs or invents on source that does
//     not compile is still a scanner that hangs or invents.
//  2. A chain through an UNRESOLVABLE LINK must end unresolved, not as a
//     PARTIAL path. `base + "/mid"` where base is unknown must not yield
//     "/mid": that is a route the server does not serve, a registry entry
//     could be written to match it, and the coverage check would then pass
//     while the real route stayed uncovered. The same failure the unresolvable
//     subrouter prefix has, one level down.
func TestAConstantChainTerminatesAndNeverInvents(t *testing.T) {
	root := writeTree(t, map[string]string{
		"svc/c.go": `package svc

import "os"

// A cycle. Go would reject this; the parser does not.
const cycleA = cycleB + "/a"
const cycleB = cycleA + "/b"

// A chain whose root is not a compile-time string at all.
var runtimeBase = os.Getenv("AXONFLOW_BASE")

var chainedOnRuntime = runtimeBase + "/mid"
var deeperOnRuntime = chainedOnRuntime + "/leaf"

// A control: an ordinary chain in the same file, so a scan that resolved
// NOTHING could not be mistaken for correct behaviour on the two above.
const goodBase = "/api/v1"
const goodLeaf = goodBase + "/good"
`,
		"svc/r.go": `package svc

import (
	"net/http"

	"github.com/gorilla/mux"
)

func R(r *mux.Router, h http.HandlerFunc) {
	r.HandleFunc(cycleA, h)
	r.HandleFunc(chainedOnRuntime, h)
	r.HandleFunc(deeperOnRuntime, h)
	r.HandleFunc(goodLeaf, h)
}
`,
	})

	done := make(chan *Derivation, 1)
	go func() {
		d, err := Derive(root, []string{"svc"})
		if err != nil {
			t.Errorf("Derive: %v", err)
			done <- &Derivation{}
			return
		}
		done <- d
	}()
	var d *Derivation
	select {
	case d = <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("Derive did not terminate on a constant cycle")
	}

	// The control first: if this is missing, the two assertions below are
	// satisfied by a scan that resolved nothing at all.
	found := map[string]bool{}
	for _, p := range d.Patterns() {
		found[p] = true
	}
	if !found["/api/v1/good"] {
		t.Fatal("the ordinary chain in the same file did not resolve, so this test cannot " +
			"tell correct refusal from a scan that failed entirely")
	}

	for _, invented := range []string{"/mid", "/mid/leaf", "/a", "/b", "/a/b", "/b/a"} {
		if found[invented] {
			t.Errorf("the scanner invented %q from a chain it could not resolve. A partial "+
				"path is a route the server does not serve, and a registry entry written to "+
				"match it would make the coverage check pass on a real route that is "+
				"uncovered", invented)
		}
	}
	// And all three unreadable registrations must be REPORTED, not dropped.
	if got := len(d.Unresolved()); got != 3 {
		t.Errorf("expected the cycle and the two runtime-rooted chains to be reported as 3 "+
			"unresolved sites, got %d: %+v", got, d.Unresolved())
	}
}

// TestASubrouterTheScannerCannotFollowIsReported covers the shape nobody
// planted, which is the point of adding it.
//
// The learners recognise three homes for a subrouter: a `:=`, a `var`, and an
// immediate chain. A subrouter stored anywhere else — a struct field, a map, a
// slice, a return value — cannot be followed, and its children would be
// recorded BARE: an invented top-level route, the same failure H1 produced, in
// a shape no reviewer has planted.
//
// There are ZERO such sites in the tree today, so the reporter finds nothing
// there. A guard that has never been shown to fire is a guard nobody can trust,
// so it fires here — and the fixture also carries the three ordinary homes,
// which must NOT be reported, because a reporter that flagged all ten real
// call sites would be worse than none.
func TestASubrouterTheScannerCannotFollowIsReported(t *testing.T) {
	root := writeTree(t, map[string]string{
		"svc/r.go": `package svc

import (
	"net/http"

	"github.com/gorilla/mux"
)

type server struct{ sub *mux.Router }

func (s *server) Unfollowable(r *mux.Router, h http.HandlerFunc) {
	// Stored in a struct field: the scanner cannot tell this from a plain
	// router at the registration below, so it must say so.
	s.sub = r.PathPrefix("/api/v1/hidden").Subrouter()
	s.sub.HandleFunc("/leaf", h)
}

// M-A: a package-level subrouter used from ANOTHER package-level initialiser,
// and one declared BEFORE its parent. Both are invisible to a per-file,
// declaration-ordered pass.
var lateChild = lateParent.HandleFunc("/late-child", nil)

var lateParent = pkgLevelRouter.PathPrefix("/api/v1/late").Subrouter()

var pkgLevelRouter = mux.NewRouter()

// A METHOD VALUE of a route method, INVOKED. The route it registers is
// invisible to a scanner that looks for a selector on a router, so it must be
// reported.
func MethodValuesInvoked(r *mux.Router, h http.HandlerFunc) {
	reg := r.HandleFunc
	reg("/api/v1/via-a-method-value", h)
	p := r.Path
	p("/api/v1/via-a-path-method-value")
}

// ...and one that is NEVER invoked, which registers nothing. This is why the
// report fires on the CALL rather than the binding: url.URL.Path is a struct
// field every handler reads, and reporting on the binding flagged four of them
// in this tree, none a route.
func NeverInvoked(req *http.Request) string {
	s := req.URL.Path
	return s
}

func Ordinary(r *mux.Router, h http.HandlerFunc) {
	a := r.PathPrefix("/api/v1/a").Subrouter()
	a.HandleFunc("/one", h)
	var b = r.PathPrefix("/api/v1/b").Subrouter()
	b.HandleFunc("/two", h)
	r.PathPrefix("/api/v1/c").Subrouter().HandleFunc("/three", h)
}
`,
	})
	d, err := Derive(root, []string{"svc"})
	if err != nil {
		t.Fatal(err)
	}

	// The three ordinary homes must resolve and must NOT be reported.
	found := map[string]bool{}
	for _, p := range d.Patterns() {
		found[p] = true
	}
	for _, want := range []string{
		"/api/v1/a/one", "/api/v1/b/two", "/api/v1/c/three",
		// Declared BEFORE its parent, and its parent before the router. A
		// per-file, declaration-ordered pass resolves none of these.
		"/api/v1/late/late-child",
	} {
		if !found[want] {
			t.Errorf("an ordinary subrouter home stopped resolving: %s", want)
		}
	}

	// The method values: exactly two reported, and the never-invoked binding
	// must contribute NOTHING. "At least one" would be satisfied by the
	// unfollowable subrouter already in this fixture.
	var methodValueSites int
	for _, site := range d.Unresolved() {
		if strings.Contains(site.Expr, "method VALUE") {
			methodValueSites++
		}
	}
	if methodValueSites != 2 {
		t.Errorf("expected exactly 2 invoked method values to be reported, got %d. Zero "+
			"means the report never fires; three means the never-invoked url.URL.Path "+
			"binding is being flagged, which is the false positive that made reporting on "+
			"the BINDING unusable", methodValueSites)
	}
	for _, p := range d.Patterns() {
		if strings.Contains(p, "method-value") {
			t.Errorf("a route registered through a method value was RESOLVED as %s; the "+
				"scanner cannot see that call and must not claim to", p)
		}
	}

	// M-A: the poison on an unfollowable home. Asserting only that the HOME is
	// reported left the CHILD unasserted, so turning the poison off survived.
	if found["/leaf"] {
		t.Error("a registration on a subrouter stored where the scanner cannot follow it " +
			"was recorded BARE as /leaf — a top-level route the server does not serve")
	}
	var poisonedChild bool
	for _, site := range d.Unresolved() {
		if strings.Contains(site.Expr, unknownPrefixNote) && strings.Contains(site.Expr, "/leaf") {
			poisonedChild = true
		}
	}
	if !poisonedChild {
		t.Error("the child of an unfollowable home was neither resolved nor poisoned")
	}

	var reportedUnfollowable int
	for _, site := range d.Unresolved() {
		if site.Method == "Subrouter" {
			reportedUnfollowable++
			if !strings.Contains(site.Expr, "cannot follow") {
				t.Errorf("the report does not say what is wrong: %q", site.Expr)
			}
		}
	}
	if reportedUnfollowable != 1 {
		t.Errorf("expected exactly 1 unfollowable subrouter to be reported, got %d. More "+
			"than one means the three ordinary homes are being flagged too, which would "+
			"make the reporter worse than none; zero means it never fires",
			reportedUnfollowable)
	}
}

// TestTheTreeHasNoUnfollowableSubrouter states the measurement the reporter
// rests on, so a future reader does not have to take "zero such sites today" on
// trust — and so the day one appears, this says so in the same breath as the
// route_exemption it will need.
func TestTheTreeHasNoUnfollowableSubrouter(t *testing.T) {
	d, _ := deriveRepo(t)
	for _, site := range d.Unresolved() {
		if site.Method == "Subrouter" {
			t.Errorf("%s binds a subrouter the scanner cannot follow, so every registration "+
				"on it is recorded without its prefix. Bind it to a plain identifier, or "+
				"add a route_exemption saying why the URL space is covered anyway",
				site.SiteKey())
		}
	}
}

// TestConstantResolutionRefusesWhatItCannotRead is the test that should have
// been in the tree two rounds ago.
//
// R3 asked for these fixtures, my push message said they were planted, and they
// were not: four mutants of the constant resolver survived the entire package.
// The claim was the failure, not the code — so this test exists to make the
// claim checkable, and each case names the mutant it kills.
//
// The four:
//
//  1. delete `|| shadowed[v.Name]` in staticStringScoped  -> the range shadow
//  2. `into[dirKey] = v` unconditionally in record()      -> the same-dir conflict
//  3. restore the skip-once-populated in resolveConsts    -> the second declaration
//  4. resolve in place instead of in Jacobi rounds        -> the dependent constant
func TestConstantResolutionRefusesWhatItCannotRead(t *testing.T) {
	root := writeTree(t, map[string]string{
		// (2) and (3): one directory, two build-tag variants, one name.
		"svc/ent.go": "//go:build enterprise\n\npackage svc\n\n" +
			"const Conflicted = \"/api/v1/ent\"\n" +
			// (4): derived from the conflicted name, and the literal lives in
			// the OTHER file, so this only resolves in a later round.
			"const Derived = Conflicted + \"/derived\"\n",
		"svc/comm.go": "//go:build !enterprise\n\npackage svc\n\n" +
			"const Base = \"/api/v1\"\n" +
			"const Conflicted = Base + \"/comm\"\n",
		// A control in the same directory: an ordinary constant that MUST
		// still resolve, so "nothing resolved" cannot be mistaken for
		// "the conflict was refused".
		"svc/ok.go": "package svc\n\nconst Fine = \"/api/v1/fine\"\n",
		// (5, M-E): ONE name, declared readably in one build-tag variant and
		// unreadably in the other. Go allows this because only one compiles;
		// go/parser reads both, and the scanner must not pick the readable one.
		"svc/mixed_ent.go":  "//go:build enterprise\n\npackage svc\n\nconst Mixed = \"/api/v1/mixed\"\n",
		"svc/mixed_comm.go": "//go:build !enterprise\n\npackage svc\n\nimport \"os\"\n\nvar Mixed = os.Getenv(\"AXONFLOW_MIXED\")\n",
		"svc/r.go": `package svc

import (
	"net/http"

	"github.com/gorilla/mux"
)

// (1) A range variable named like a package constant. Without the shadow
// check, ` + "`route`" + ` resolves to the constant and the scanner reports a route
// the loop never registers.
const route = "/api/v1/from-the-package-constant"

func Register(r *mux.Router, h http.HandlerFunc, paths []string) {
	r.HandleFunc(Fine, h)
	r.HandleFunc(Conflicted, h)
	r.HandleFunc(Derived, h)
	r.HandleFunc(Mixed, h)
	for _, route := range paths {
		r.HandleFunc(route, h)
	}
}
`,
	})
	d, err := Derive(root, []string{"svc"})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, p := range d.Patterns() {
		found[p] = true
	}

	// The control FIRST. Without it, every refusal below is equally well
	// explained by a resolver that stopped working.
	if !found["/api/v1/fine"] {
		t.Fatal("the ordinary constant in the same directory did not resolve, so this test " +
			"cannot tell a correct refusal from a broken resolver")
	}

	for name, invented := range map[string]string{
		"the same-directory conflict (mutants 2 and 3)":            "/api/v1/ent",
		"the other side of the same conflict":                      "/api/v1/comm",
		"a constant DERIVED from a conflicted one (mutant 4)":      "/api/v1/ent/derived",
		"the other side of the derived one":                        "/api/v1/comm/derived",
		"a range variable shadowing a package constant (mutant 1)": "/api/v1/from-the-package-constant",
		"a name also declared as an unreadable var (M-E)":          "/api/v1/mixed",
	} {
		if found[invented] {
			t.Errorf("%s: the scanner resolved %s. It cannot know which declaration the "+
				"identifier means, and answering anyway is how a census claims coverage of "+
				"a URL space it could not read", name, invented)
		}
	}

	// And every one of them must be REPORTED, not dropped. Exact count: four
	// registrations the scanner cannot read (Conflicted, Derived, Mixed, route).
	if got := len(d.Unresolved()); got != 4 {
		t.Errorf("expected exactly 4 unresolved registrations, got %d: %+v",
			got, d.Unresolved())
	}
}

// TestTheConflictedAnswerDoesNotDependOnFileOrder pins R4-2's other half.
//
// The reason this shape reaches the transitive propagation is TIMING, not file
// order. Round 1 resolves the LITERAL P and, in the same round, Q = P + "/x",
// and commits both. The other P cannot resolve until Base does, so the conflict
// only appears in round 2 — after Q is already committed. Unresolved-spec
// poisoning cannot catch that, because at the moment Q resolved nothing was
// unresolved; only a pass back over the resolved set can undo it.
//
// Both orders are run because the answer WAS order-dependent: before the fix
// this gave /ent/x one way and /comm/x the other, which is not a fact about the
// platform, it is a fact about which file the walk reached first.
func TestTheConflictedAnswerDoesNotDependOnFileOrder(t *testing.T) {
	build := func(literalInA bool) (map[string]bool, []RouteSite) {
		a := "//go:build enterprise\n\npackage svc\n\nconst P = \"/api/v1/ent\"\nconst Q = P + \"/x\"\n"
		b := "//go:build !enterprise\n\npackage svc\n\nconst Base = \"/api/v1\"\nconst P = Base + \"/comm\"\n"
		if !literalInA {
			a = "//go:build enterprise\n\npackage svc\n\nconst Base = \"/api/v1\"\nconst P = Base + \"/ent\"\nconst Q = P + \"/x\"\n"
			b = "//go:build !enterprise\n\npackage svc\n\nconst P = \"/api/v1/comm\"\n"
		}
		root := writeTree(t, map[string]string{
			"svc/a.go":  a,
			"svc/b.go":  b,
			"svc/ok.go": "package svc\n\nconst Control = \"/api/v1/control\"\n",
			"svc/r.go": `package svc

import (
	"net/http"

	"github.com/gorilla/mux"
)

func R(r *mux.Router, h http.HandlerFunc) {
	r.HandleFunc(Control, h)
	r.HandleFunc(Q, h)
}
`,
		})
		d, err := Derive(root, []string{"svc"})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, p := range d.Patterns() {
			out[p] = true
		}
		return out, d.Unresolved()
	}
	for _, literalInA := range []bool{true, false} {
		where := map[bool]string{true: "the enterprise", false: "the community"}[literalInA]
		got, unresolved := build(literalInA)
		if !got["/api/v1/control"] {
			t.Fatalf("with the literal in %s file, the control constant did not resolve", where)
		}
		for _, invented := range []string{"/api/v1/ent/x", "/api/v1/comm/x"} {
			if got[invented] {
				t.Errorf("with the literal in %s file, a constant derived from a CONFLICTED "+
					"one resolved to %s. Which value it picked was decided by which file "+
					"the walk reached first, which is not a fact about the platform",
					where, invented)
			}
		}
		var reported bool
		for _, site := range unresolved {
			if site.Expr == "Q" {
				reported = true
			}
		}
		if !reported {
			t.Errorf("with the literal in %s file, the registration through Q was neither "+
				"resolved nor reported", where)
		}
	}
}

// TestAConstantCommittedBeforeItsParentIsPoisonedIsRevisited is the fixture the
// transitive propagation actually needs, and it took three attempts to build.
//
// The propagation exists because a derived constant can be COMMITTED in a round
// that runs before its parent's conflicting declaration is read. My first two
// fixtures could not reach it: in both, the file holding the conflict sorted
// early enough that the parent was already poisoned when the derived constant
// was tried, so the unresolved-spec poisoning caught it and the propagation was
// never exercised. Removing the propagation survived both.
//
// The shape that reaches it: the derived constant AND one declaration of its
// parent in a file that sorts BEFORE the conflicting declaration, so the
// derived value is resolved and committed first and only a second pass can
// undo it. `aaa.go` and `zzz.go` are named for their sort order, which is the
// load-bearing part of this fixture.
func TestAConstantCommittedBeforeItsParentIsPoisonedIsRevisited(t *testing.T) {
	root := writeTree(t, map[string]string{
		"svc/aaa.go": "//go:build enterprise\n\npackage svc\n\n" +
			"const Parent = \"/api/v1/first\"\n" +
			"const Child = Parent + \"/child\"\n",
		"svc/zzz.go": "//go:build !enterprise\n\npackage svc\n\n" +
			"const Parent = \"/api/v1/second\"\n",
		"svc/ok.go": "package svc\n\nconst Control = \"/api/v1/control\"\n",
		"svc/r.go": `package svc

import (
	"net/http"

	"github.com/gorilla/mux"
)

func R(r *mux.Router, h http.HandlerFunc) {
	r.HandleFunc(Control, h)
	r.HandleFunc(Child, h)
}
`,
	})
	d, err := Derive(root, []string{"svc"})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, p := range d.Patterns() {
		found[p] = true
	}
	if !found["/api/v1/control"] {
		t.Fatal("the control constant did not resolve, so a refusal below proves nothing")
	}
	if found["/api/v1/first/child"] || found["/api/v1/second/child"] {
		t.Error("a constant derived from a CONFLICTED parent kept the value it was " +
			"committed with. It was resolved in a pass that ran before the conflicting " +
			"declaration was read, so only a second pass over the resolved set can undo " +
			"it — which is the whole reason the propagation exists")
	}
	var reported bool
	for _, site := range d.Unresolved() {
		if site.Expr == "Child" {
			reported = true
		}
	}
	if !reported {
		t.Error("the registration through the derived constant was neither resolved nor " +
			"reported")
	}
}

// TestPackageLevelSubroutersRefuseWhatTheyCannotPrice covers the two shapes
// round 5 found, and the rule they come from: the scanner REPORTS what it
// cannot prove, and prices a receiver only where a fixture proves it can.
//
// The defect both shared: an identifier naming a subrouter whose prefix was not
// yet known was treated as the ROOT. That is the one reading it must never
// take — a name we know something about and cannot price is the opposite of a
// name we know nothing about.
func TestPackageLevelSubroutersRefuseWhatTheyCannotPrice(t *testing.T) {
	// 1. A child declared ABOVE its parent, and its parent above the router.
	// A single pass, or a fixpoint that treats an unpriced receiver as the
	// root, gives the child the prefix "/b" and its registration "/b/c".
	childFirst := writeTree(t, map[string]string{
		"svc/a.go": `package svc

import "github.com/gorilla/mux"

var pkgB = pkgA.PathPrefix("/b").Subrouter()

var pkgA = rootRouter.PathPrefix("/a").Subrouter()

var rootRouter = mux.NewRouter()

func R() { pkgB.HandleFunc("/c", nil) }
`,
	})
	d, err := Derive(childFirst, []string{"svc"})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, p := range d.Patterns() {
		found[p] = true
	}
	if !found["/a/b/c"] {
		t.Errorf("a child subrouter declared ABOVE its parent did not resolve to /a/b/c; "+
			"got %v", d.Patterns())
	}
	if found["/b/c"] || found["/c"] {
		t.Error("a child subrouter declared above its parent was priced from the ROOT — a " +
			"path no server serves. An unpriced receiver is not the root")
	}
	if got := len(d.Unresolved()); got != 0 {
		t.Errorf("nothing here is unreadable, so nothing should be reported; got %d: %+v",
			got, d.Unresolved())
	}

	// 2. BUILD-TAG TWINS at package level. Two declarations of one name with
	// different prefixes: poisoned, never picked between, and the registration
	// reported.
	twins := writeTree(t, map[string]string{
		"svc/ent.go":  "//go:build enterprise\n\npackage svc\n\nvar twin = rootRouter.PathPrefix(\"/ent\").Subrouter()\n",
		"svc/comm.go": "//go:build !enterprise\n\npackage svc\n\nvar twin = rootRouter.PathPrefix(\"/comm\").Subrouter()\n",
		"svc/r.go": `package svc

import "github.com/gorilla/mux"

var rootRouter = mux.NewRouter()

func R() { twin.HandleFunc("/leaf", nil) }
`,
	})
	d2, err := Derive(twins, []string{"svc"})
	if err != nil {
		t.Fatal(err)
	}
	found2 := map[string]bool{}
	for _, p := range d2.Patterns() {
		found2[p] = true
	}
	// The two PathPrefix calls are themselves real claims on the URL space and
	// are recorded; the CHILD is what must not be.
	for _, invented := range []string{"/ent/leaf", "/comm/leaf", "/leaf"} {
		if found2[invented] {
			t.Errorf("a registration on a package-level subrouter declared TWICE with "+
				"different prefixes resolved to %s, which is a value chosen by walk order",
				invented)
		}
	}
	if got := len(d2.Unresolved()); got != 1 {
		t.Errorf("expected exactly 1 reported registration on the twinned subrouter, got "+
			"%d: %+v", got, d2.Unresolved())
	}

	// 3. A subrouter hung off something other than NewRoute/PathPrefix. The
	// scanner cannot say what region of the URL space it covers, so it refuses.
	other := writeTree(t, map[string]string{
		"svc/r.go": `package svc

import "github.com/gorilla/mux"

func R(r *mux.Router) {
	sub := r.Path("/exact").Subrouter()
	sub.HandleFunc("/child", nil)
}
`,
	})
	d3, err := Derive(other, []string{"svc"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range d3.Patterns() {
		if p == "/child" || p == "/exact/child" {
			t.Errorf("a subrouter hung off Path() was priced as %s; this scanner does not "+
				"know what region that covers and must say so", p)
		}
	}
	var reported bool
	for _, site := range d3.Unresolved() {
		if strings.Contains(site.Expr, unknownPrefixNote) {
			reported = true
		}
	}
	if !reported {
		t.Error("a subrouter hung off Path() was neither priced nor reported")
	}
}

// TestMethodValuesSurviveOneIndirection is M-2. A method value that is aliased,
// captured by a closure, or handed to another function was silent — one
// indirection was enough.
func TestMethodValuesSurviveOneIndirection(t *testing.T) {
	root := writeTree(t, map[string]string{
		"svc/r.go": `package svc

import (
	"net/http"

	"github.com/gorilla/mux"
)

func apply(f func(string, func(http.ResponseWriter, *http.Request)) *mux.Route) {}

func Indirect(r *mux.Router, h http.HandlerFunc) {
	reg := r.HandleFunc
	alias := reg
	alias("/api/v1/through-an-alias", h)

	inner := func() { reg("/api/v1/through-a-closure", h) }
	_ = inner

	handed := r.HandleFunc
	apply(handed)
	// The DIRECT argument form, with no binding at all.
	apply(r.HandleFunc)
}

// M-B: the same thing bound with a var declaration rather than :=, inside a
// function and at package level. The learner watched only AssignStmt, so both
// were silent.
var pkgReg = pkgRouterForMV.HandleFunc

var pkgRouterForMV = mux.NewRouter()

func VarForms(r *mux.Router, h http.HandlerFunc) {
	var vreg = r.Handle
	vreg("/api/v1/through-a-var", nil)
	pkgReg("/api/v1/through-a-package-var", h)

	// The AMBIGUOUS name in var form. Path is not in the one-rule sweep, so
	// this binding is reported only when INVOKED, and the invocation is what
	// the in-function var learner has to have recorded. Without that learner
	// the call matches nothing and the route is dropped silently, which is the
	// direction the sweep cannot cover.
	var vpath = r.Path
	vpath("/api/v1/through-a-var-path")

	// The ambiguous name through a VAR ALIAS of a binding. This is the one
	// shape the round-8 sweep cannot reach and the var-alias learner is the
	// only thing carrying: the sweep skips Path by design, so if the alias
	// does not inherit the method value, the call through it matches nothing
	// and the registration is DROPPED with no site at all.
	af := r.Path
	var ag = af
	ag("/api/v1/through-a-var-alias-path")
}

// THE TWO REAL SHAPES FROM THIS TREE, and the reason the ambiguous-name rule
// is what it is. Both are url.URL.Path, neither is a route, and both would be
// reported if the rule were widened to cover an ambiguous name passed
// somewhere. platform/orchestrator/ojk/ojk_audit_export_handlers.go and
// platform/orchestrator/rbi/wire.go each hold one; widening the rule reported
// both, which is why it is not widened.
func NotAMethodValue(req *http.Request) string {
	path := req.URL.Path
	return path
}

func NotAMethodValueButPassed(req *http.Request) {
	path := req.URL.Path
	consume(path)
}

func consume(string) {}

// ROUND 8: the shapes four position-enumerating detectors could not see. A
// method value placed in a composite literal, a map literal or a struct field
// and called later produced NO SITE AT ALL — the silent-drop direction.
type mvHolder struct {
	reg func(string, http.HandlerFunc) *mux.Route
}

func InLiterals(r *mux.Router, h http.HandlerFunc) {
	holder := mvHolder{reg: r.HandleFunc}
	holder.reg("/api/v1/through-a-struct-literal", h)

	table := map[string]func(string, http.HandlerFunc) *mux.Route{
		"a": r.HandleFunc,
	}
	table["a"]("/api/v1/through-a-map-literal", h)

	list := []func(string, http.HandlerFunc) *mux.Route{r.HandleFunc}
	list[0]("/api/v1/through-a-slice-literal", h)
}

// THE ACCEPTED FALSE POSITIVE, pinned so it is a visible choice rather than a
// surprise. Handle is an unambiguous route method AND a method on
// slog.Handler, http.Handler and anything else; without types the sweep cannot
// tell them apart, so a non-router Handle method value IS reported. The tree
// has zero reported method values of any name today, so the rate is zero; this
// fixture is what makes a future non-zero one a change somebody has to look at.
type notARouter struct{}

func (notARouter) Handle(string, http.Handler) {}

func FalsePositive(n notARouter) {
	apply2(n.Handle)
}

func apply2(func(string, http.Handler)) {}

// A method value RETURNED, and one inside a deferred call. Same rule, no new
// arm: the sweep does not know what a return or a defer is.
func Returned(r *mux.Router) func(string, http.HandlerFunc) *mux.Route {
	defer apply(r.HandleFunc)
	return r.HandleFunc
}
`,
	})
	d, err := Derive(root, []string{"svc"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range d.Patterns() {
		if strings.Contains(p, "through-an") || strings.Contains(p, "through-a") {
			t.Errorf("a route registered through an indirected method value was RESOLVED "+
				"as %s; the scanner cannot see that call", p)
		}
	}
	var reported int
	for _, site := range d.Unresolved() {
		if strings.Contains(site.Expr, "method VALUE") {
			reported++
		}
	}
	// ONE SITE PER HANDING, not one per use. Round 8 replaced four
	// position-enumerating detectors with a single rule — a SelectorExpr
	// naming an unambiguous route method and not being CALLED is a method
	// value — so `handed := r.HandleFunc; apply(handed)` is one site (the
	// handing) rather than two (the binding and the pass). Counting uses was
	// what made the old detectors have to enumerate positions at all.
	//
	// The ten, each a distinct SelectorExpr that is handed rather than called:
	// `reg := r.HandleFunc`, `handed := r.HandleFunc`, the direct
	// `apply(r.HandleFunc)`, the package-level `var pkgReg = …HandleFunc`, the
	// in-function `var vreg = r.Handle`, and round 8's five — a struct
	// literal, a map literal, a slice literal, a `return` and a `defer`.
	//
	// READ THE COUNT CORRECTLY. It is a count of HANDINGS, not of hidden
	// routes. `alias := reg; alias("/x", h)` and the closure that calls `reg`
	// add no site: the fact that routes registered through `reg` are invisible
	// was already stated where `reg` was bound, and counting uses is what
	// forced the previous four detectors to enumerate syntactic positions —
	// which is how a struct-literal method value came to produce NO site at
	// all. One rule, one site per handing.
	//
	// The two url.URL.Path bindings contribute NOTHING: `Path` is ambiguous,
	// is not in this sweep, and is reported only when invoked.
	// Eleven, not ten: the accepted false positive above is the eleventh, and
	// counting it here is the point — it is reported, deliberately, and a
	// change to that is a change to this number.
	const wantMV = 11
	// Plus the two invoked ambiguous bindings — the `var` form and the `var`
	// ALIAS of a `:=` form — which the sweep does not see and only the
	// in-function learners can report.
	if reported != wantMV+2 {
		t.Errorf("expected exactly %d reported method-value sites, got %d: %+v.\n\nMore means "+
			"the two url.URL.Path bindings in this fixture are being reported: one is never "+
			"used and one is PASSED to a function, and neither is a route. Both shapes are "+
			"real - ojk_audit_export_handlers.go and rbi/wire.go each hold one - which is "+
			"why an AMBIGUOUS method name is reported when INVOKED and not when merely "+
			"passed. Fewer means a syntactic position is being missed, which is the "+
			"silent-drop direction: a struct-literal or map-literal method value produced "+
			"NO site at all before round 8",
			wantMV+2, reported, d.Unresolved())
	}
}

// TestCrossPackageConstantResolutionIsPinned covers the four resolution paths
// round 5 found unpinned: the package-qualified key, its ambiguity sentinel,
// the parenthesised expression, and the concatenation recursion.
//
// Each is a branch of staticStringScoped that no fixture reached, so each could
// be deleted and the whole package stayed green. The cases below are named for
// the branch they exercise.
func TestCrossPackageConstantResolutionIsPinned(t *testing.T) {
	root := writeTree(t, map[string]string{
		"pkg/paths/paths.go": "package paths\n\n" +
			"const Exported = \"/api/v1/cross-package\"\n" +
			"const Parenthesised = (\"/api/v1/paren\")\n",
		"svc/r.go": `package svc

import (
	"net/http"

	"example/pkg/paths"

	"github.com/gorilla/mux"
)

const localHalf = "/api/v1"

func R(r *mux.Router, h http.HandlerFunc) {
	r.HandleFunc(paths.Exported, h)
	r.HandleFunc(paths.Parenthesised, h)
	r.HandleFunc(localHalf+"/concatenated", h)
	r.HandleFunc(("/api/v1/local-paren"), h)
}
`,
	})
	d, err := Derive(root, []string{"pkg", "svc"})
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, p := range d.Patterns() {
		found[p] = true
	}
	for branch, want := range map[string]string{
		"the package-qualified key":                   "/api/v1/cross-package",
		"a parenthesised constant in another package": "/api/v1/paren",
		"the concatenation recursion":                 "/api/v1/concatenated",
		"a parenthesised literal at the call site":    "/api/v1/local-paren",
	} {
		if !found[want] {
			t.Errorf("%s did not resolve (%s); that branch of the resolver is unreached by "+
				"every other fixture, so nothing else would notice it going", branch, want)
		}
	}
	if got := len(d.Unresolved()); got != 0 {
		t.Errorf("everything here is readable; got %d unresolved: %+v", got, d.Unresolved())
	}
}

// TestAConstantChainResolvesHoweverItIsOrdered pins the fixpoint BOUND.
//
// resolveConsts iterates until no spec resolves, bounded by len(specs)+1. A
// chain declared in the worst order — each constant defined in terms of the one
// declared after it — needs one round per link, so a bound of two rounds (or a
// single pass) leaves the tail unresolved and the routes built on it reported
// as unknown. Nothing else in the package declares a chain deeper than two, so
// the bound could be cut to a constant and every other test stayed green.
//
// Declared across four files in reverse dependency order, because within one
// file the walk order alone would hide the defect.
func TestAConstantChainResolvesHoweverItIsOrdered(t *testing.T) {
	root := writeTree(t, map[string]string{
		"svc/a.go": "package svc\n\nconst L4 = L3 + \"/four\"\n",
		"svc/b.go": "package svc\n\nconst L3 = L2 + \"/three\"\n",
		"svc/c.go": "package svc\n\nconst L2 = L1 + \"/two\"\n",
		"svc/d.go": "package svc\n\nconst L1 = \"/one\"\n",
		"svc/r.go": `package svc

import (
	"net/http"

	"github.com/gorilla/mux"
)

func R(r *mux.Router, h http.HandlerFunc) {
	r.HandleFunc(L4, h)
}
`,
	})
	d, err := Derive(root, []string{"svc"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(d.Patterns(), "/one/two/three/four") {
		t.Errorf("a four-link constant chain declared in reverse order did not resolve; the "+
			"fixpoint stopped short of its bound. patterns=%v unresolved=%+v",
			d.Patterns(), d.Unresolved())
	}
	if got := len(d.Unresolved()); got != 0 {
		t.Errorf("everything here is readable; got %d unresolved: %+v", got, d.Unresolved())
	}
}

// TestAPackageLevelSubrouterChainResolvesHoweverTheFilesAreOrdered pins the
// SUBROUTER fixpoint's bound, which is a different loop from the constant one.
//
// A three-deep package-level chain declared across three files in reverse
// dependency order needs one round per link. Nothing else in the package
// declares a package-level chain deeper than one, so the bound could be cut to
// `round <= 1` and every other test stayed green.
//
// The fixpoint iterates its candidates in SORTED order for this test's sake as
// much as the tree's: map iteration order is random, so an unsorted fixpoint
// closes a two-link chain in one round on some runs and two on others, and a
// mutant of the bound kills intermittently. A flaky kill is read as a flaky
// test and the pin gets deleted.
func TestAPackageLevelSubrouterChainResolvesHoweverTheFilesAreOrdered(t *testing.T) {
	root := writeTree(t, map[string]string{
		// Named so that SORTED order is the reverse of dependency order —
		// aLeaf needs bMid needs cTop. File order alone is not enough: the
		// fixpoint iterates its candidates sorted, so names chosen the other
		// way round close the whole chain in a single round and a mutant of
		// the bound survives. This is the fixture that failed to kill first
		// time for exactly that reason.
		"svc/a.go": "package svc\n\nvar aLeaf = bMid.PathPrefix(\"/leaf\").Subrouter()\n",
		"svc/b.go": "package svc\n\nvar bMid = cTop.PathPrefix(\"/mid\").Subrouter()\n",
		"svc/c.go": "package svc\n\nvar cTop = rootR.PathPrefix(\"/top\").Subrouter()\n",
		"svc/d.go": "package svc\n\nimport \"github.com/gorilla/mux\"\n\nvar rootR = mux.NewRouter()\n",
		"svc/r.go": "package svc\n\nfunc R() { aLeaf.HandleFunc(\"/x\", nil) }\n",
	})
	d, err := Derive(root, []string{"svc"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(d.Patterns(), "/top/mid/leaf/x") {
		t.Errorf("a three-link package-level subrouter chain declared in reverse order did "+
			"not resolve; the subrouter fixpoint stopped short of its bound. patterns=%v "+
			"unresolved=%+v", d.Patterns(), d.Unresolved())
	}
	if got := len(d.Unresolved()); got != 0 {
		t.Errorf("every link here is provable; got %d unresolved: %+v", got, d.Unresolved())
	}
}

// TestPoisonPropagatesAcrossPackagesAndAlongAChain pins the two survivors the
// round-6 poison work left: the transitive loop's BOUND at derive.go:377, and
// the cross-package key that referencedKeys builds at :407.
//
// The existing poison fixtures are all one hop and all same-package, so the
// propagation loop could be cut to a single round and `referencedKeys` could
// stop reading SelectorExprs entirely, and every one of them stayed green.
//
//	QQ = Q + "/qq", Q = svc.P + "/q", and svc.P is poisoned.
//
// P is disqualified by an unreadable twin in a same-named package, so the
// package-qualified key is the only way to see it; Q commits in the round P
// becomes readable and must be revisited; QQ commits in the round after that
// and must be revisited AGAIN, which one round of propagation cannot do.
func TestPoisonPropagatesAcrossPackagesAndAlongAChain(t *testing.T) {
	root := writeTree(t, map[string]string{
		"pkg/paths/paths.go":   "package paths\n\nconst P = \"/api/v1/one\"\nconst Clean = \"/api/v1/clean\"\n",
		"other/paths/paths.go": "package paths\n\nimport \"os\"\n\nvar P = os.Getenv(\"AXONFLOW_P\")\n",
		"svc/derived.go": "package svc\n\nimport \"example/pkg/paths\"\n\n" +
			// QQ is declared BEFORE Q on purpose. Within one round the specs
			// are visited in order and resolution is in place, so declaring Q
			// first lets a single round poison both — and a mutant that cuts
			// the loop to one round survives. Declared this way, QQ is passed
			// over in the round that poisons Q and can only be caught by the
			// next one.
			"const QQ = Q + \"/qq\"\nconst Q = paths.P + \"/q\"\n" +
			"const CleanQ = paths.Clean + \"/q\"\n",
		"svc/r.go": `package svc

import (
	"net/http"

	"github.com/gorilla/mux"
)

func R(r *mux.Router, h http.HandlerFunc) {
	r.HandleFunc(QQ, h)
	r.HandleFunc(CleanQ, h)
}
`,
	})
	d, err := Derive(root, []string{"pkg", "other", "svc"})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"/api/v1/one/q/qq", "/api/v1/one/q", "/q/qq"} {
		if slices.Contains(d.Patterns(), bad) {
			t.Errorf("derived %q. QQ is two hops from a POISONED cross-package constant; "+
				"one hop of propagation, or a referencedKeys that cannot see a "+
				"package-qualified reference, lets the value committed before the poison "+
				"landed survive all the way to a registered path", bad)
		}
	}
	// The control, in the same assertion: a chain of exactly the same shape
	// whose root is READABLE must still resolve, so a propagation pass that
	// poisoned everything would fail here rather than pass above.
	if !slices.Contains(d.Patterns(), "/api/v1/clean/q") {
		t.Errorf("control: the clean cross-package chain did not resolve, so the negative "+
			"assertion above is vacuous — a scanner that poisoned every derived constant "+
			"would pass it. patterns=%v", d.Patterns())
	}
	if got := len(d.Unresolved()); got != 1 {
		t.Errorf("expected exactly the QQ registration to be unresolved, got %d: %+v",
			got, d.Unresolved())
	}
}

// TestOnlyAProvenReceiverIsPriced is round 8's rule, and the shapes seven
// rounds of enumerating what to REFUSE could not reach.
//
//	A receiver is UNKNOWN unless it is one of four proven shapes:
//	  (a) a function parameter or receiver;
//	  (b) a local `:=`/`var` whose value is `mux.NewRouter()` or a
//	      PathPrefix/NewRoute chain rooted in an already-priced receiver;
//	  (c) a package-level name whose single ValueSpec value is such a chain
//	      rooted in `var x = mux.NewRouter()` or another priced package-level
//	      name, resolved to a fixpoint over ALL files before any body is walked;
//	  (d) the immediate chained form.
//
// Everything else is reported. `mustNot` names the paths a wrong answer would
// invent; `unresolved` is exact, because "at least one" would pass a scanner
// that reported everything and resolved nothing.
func TestOnlyAProvenReceiverIsPriced(t *testing.T) {
	for name, tc := range map[string]struct {
		files      map[string]string
		mustNot    []string
		mustHave   []string
		unresolved int
	}{
		// R7-1. Master reproduced the R6-1 shape with the init() file sorting
		// BEFORE the declaration file and it was root-priced again: the old
		// classifier only poisoned an assigned name that was ALREADY in its
		// candidate map, so the answer depended on which file the walk reached
		// first. Both orders are planted; under the inversion neither can
		// resolve, because "assigned in a body" is simply not on the list.
		"assigned in a body, init file first": {
			files: map[string]string{
				"svc/a_init.go": `package svc

func init() { assignedLater = rootR.PathPrefix("/m").Subrouter() }
`,
				"svc/z_decl.go": `package svc

import "github.com/gorilla/mux"

var rootR = mux.NewRouter()

var assignedLater *mux.Router

func R() { assignedLater.HandleFunc("/y", nil) }
`,
			},
			mustNot: []string{"/y", "/m/y"}, unresolved: 1},
		"assigned in a body, declaration file first": {
			files: map[string]string{
				"svc/a_decl.go": `package svc

import "github.com/gorilla/mux"

var rootR = mux.NewRouter()

var assignedLater *mux.Router

func R() { assignedLater.HandleFunc("/y", nil) }
`,
				"svc/z_init.go": `package svc

func init() { assignedLater = rootR.PathPrefix("/m").Subrouter() }
`,
			},
			mustNot: []string{"/y", "/m/y"}, unresolved: 1},

		// M8-2. A VALUED declaration reassigned in a body, which is the only
		// shape that reaches the `!assignedInBody[name]` clauses at all.
		//
		// The three fixtures above all use a VALUELESS `var x *mux.Router`,
		// so the classifier's twin/multi-value arm poisons them before it ever
		// consults `assignedInBody` — every one of them passes with both clauses
		// deleted. A fixture that cannot express the defect reads as a
		// disproof of it, and this is the fourth time on this lane that a
		// fixture could not reach its own subject.
		//
		// Here the declaration PROVES a root (or a chain), so nothing else
		// poisons it: only the reassignment can, and only if it is looked at.
		"a valued root reassigned in a body": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

var rootR = mux.NewRouter()

func other() *mux.Router { return nil }

func swap() { rootR = other() }

func R(param *mux.Router) {
	rootR.HandleFunc("/x", nil)
	param.HandleFunc("/control", nil)
}
`},
			mustNot: []string{"/x"}, mustHave: []string{"/control"}, unresolved: 1},

		"a valued subrouter chain reassigned in a body": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

var rootR = mux.NewRouter()
var sub = rootR.PathPrefix("/a").Subrouter()

func other() *mux.Router { return nil }

func swap() { sub = other() }

func R() {
	sub.HandleFunc("/y", nil)
	rootR.HandleFunc("/control", nil)
}
`},
			mustNot: []string{"/y", "/a/y"}, mustHave: []string{"/control"}, unresolved: 1},

		// R7-2. A package-level ALIAS of a priced subrouter. The old
		// classifier saw no Subrouter value on `aliasSub` and skipped it
		// entirely, so the body walk found an unknown identifier and priced it
		// from the root: /x invented.
		"a package-level alias of a priced subrouter": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

var rootR = mux.NewRouter()
var sub = rootR.PathPrefix("/a").Subrouter()
var aliasSub = sub

// The same alias used OUTSIDE any function body, which is a separate walk with
// its own receiver-pricing switch. Both defaults have to be inverted; inverting
// one leaves the other pricing an unknown name at the root.
var _ = aliasSub.HandleFunc("/pkg-alias", nil)

func R() {
	aliasSub.HandleFunc("/x", nil)
	sub.HandleFunc("/control", nil)
}
`},
			mustNot:  []string{"/x", "/a/x", "/pkg-alias", "/a/pkg-alias"},
			mustHave: []string{"/a/control"}, unresolved: 2},

		// R7-3. Assigned from a PARAMETER and from a CALL. Neither has a
		// Subrouter value, so neither was poisoned; both were priced at the
		// root.
		"a package-level name assigned from a parameter or a call": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

var rootR = mux.NewRouter()
var fromParam *mux.Router
var fromCall *mux.Router

func Wire(r *mux.Router) { fromParam = r }

func init() { fromCall = newSub() }

func newSub() *mux.Router { return rootR.PathPrefix("/n").Subrouter() }

func R() {
	fromParam.HandleFunc("/p", nil)
	fromCall.HandleFunc("/c", nil)
	rootR.HandleFunc("/control", nil)
}
`},
			// Three, not two: `return rootR.PathPrefix("/n").Subrouter()` is
			// itself a subrouter bound to nothing the scanner can follow, and
			// the older guard reports it where it is BUILT as well as where it
			// is used. Both reports are wanted — one names the escape, the
			// other names the registration that escaped with it.
			mustNot: []string{"/p", "/c", "/n/c"}, mustHave: []string{"/control"}, unresolved: 3},

		// R7-4. A known subrouter reached through a shape that is not a plain
		// identifier: parenthesised, indexed out of a slice, out of a map, and
		// the range variable. Each invented a top-level path.
		"a known subrouter reached through a parenthesis, an index, a map or a range": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

func R(r *mux.Router) {
	sub := r.PathPrefix("/a").Subrouter()
	(sub).HandleFunc("/paren", nil)

	subs := []*mux.Router{sub}
	subs[0].HandleFunc("/index", nil)

	m := map[string]*mux.Router{"k": sub}
	m["k"].HandleFunc("/map", nil)

	for _, each := range subs {
		each.HandleFunc("/range", nil)
		// A CHAIN built on the unprovable name, which is the shape that
		// reaches subrouterPrefix rather than the call site: if its base
		// started at the root again, this would come out at /chained/deep.
		deep := each.PathPrefix("/chained").Subrouter()
		deep.HandleFunc("/deep", nil)
	}
	sub.HandleFunc("/control", nil)
}
`},
			mustNot: []string{"/paren", "/index", "/map", "/range",
				"/a/paren", "/a/index", "/a/map", "/a/range",
				"/chained/deep", "/a/chained/deep", "/deep"},
			// Six: the four registrations on unprovable receivers, plus the
			// PathPrefix of the chain built on one (itself a registration
			// method) and the child registered on that chain.
			mustHave: []string{"/a/control"}, unresolved: 6},

		// A parameter reassigned INSIDE A CLOSURE. The reassignment sweep
		// used to skip FuncLits — correct for `:=` bindings, which are the
		// closure's own scope, and wrong for `=` assignments, which write to
		// the name the closure closed over. The registration after it was
		// still priced as the parameter that had been swapped out.
		"a parameter reassigned inside a closure": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

func other() *mux.Router { return nil }

func R(r *mux.Router, safe *mux.Router) {
	swap := func() { r = other() }
	_ = swap
	r.HandleFunc("/swapped", nil)
	safe.HandleFunc("/control", nil)
}
`},
			mustNot: []string{"/swapped"}, mustHave: []string{"/control"}, unresolved: 1},

		// A closure INHERITS the roots its enclosing body proved. Without
		// that, every registration inside a closure on the enclosing
		// function's own parameter is reported — which is the over-poisoning
		// direction, but it is still wrong and it is common in this tree.
		"a closure registering on its enclosing function's parameter": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

func R(r *mux.Router) {
	inner := func() { r.HandleFunc("/in-closure", nil) }
	_ = inner
	r.HandleFunc("/control", nil)
}
`},
			mustHave: []string{"/in-closure", "/control"}, unresolved: 0},

		// A LOCAL that shadows a package-level PENDING name, and is itself
		// proven. `pending` and the package subrouter map are disjoint by
		// construction, but `pending` and a BODY's subrouter map are not: a
		// local `:=` can bind a name the package also declares. Consulting
		// package-level `pending` first then poisoned a local the body had
		// just proved — over-poisoning, the safe direction, but wrong, and it
		// hid the fact that the arm was doing anything at all.
		"a proven local shadowing a package-level pending name": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

var rootR = mux.NewRouter()

var shadowed *mux.Router

func init() { shadowed = rootR.PathPrefix("/pkg").Subrouter() }

func R(r *mux.Router) {
	shadowed := r.PathPrefix("/local").Subrouter()
	child := shadowed.PathPrefix("/c").Subrouter()
	child.HandleFunc("/leaf", nil)
}
`},
			mustHave: []string{"/local/c/leaf"}, unresolved: 0},

		// A `:=` LOCAL SHADOWING A PROVEN PACKAGE ROOT. The other direction
		// of the same line, and the one nothing pinned.
		//
		// Round 9 made `assignedInBody` skip `token.DEFINE` — correct, because
		// a `:=` only ever binds a local — which left `bodyBound` as the SOLE
		// mechanism stopping a shadowing local from inheriting the package
		// root's price. Only the over-poisoning direction had a fixture, so
		// disarming `bodyBound` invented `/shadowed` and nothing noticed. A
		// guard that trades one direction for the other needs a case in both.
		"a local shadowing a proven package root": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

var rootR = mux.NewRouter()

func other() *mux.Router { return nil }

func R() {
	rootR := other()
	rootR.HandleFunc("/shadowed", nil)
}

func Control() { rootR.HandleFunc("/control", nil) }
`},
			mustNot: []string{"/shadowed"}, mustHave: []string{"/control"}, unresolved: 1},

		// A PARAMETER REASSIGNED in the body is no longer the router that was
		// handed in, so rule (a) stops applying to it.
		"a parameter reassigned in the body": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

func pick() *mux.Router { return nil }

func R(r *mux.Router, other *mux.Router) {
	r = pick()
	r.HandleFunc("/reassigned", nil)
	other.HandleFunc("/control", nil)
}
`},
			mustNot: []string{"/reassigned"}, mustHave: []string{"/control"}, unresolved: 1},

		// A package-level name assigned a root INSIDE a body, pinned by a
		// FIXTURE rather than by `platform/agent/run.go`'s globalRouter — a
		// change to that one file would have taken the pin with it and the
		// mutant would have read as unkillable.
		"a valueless *mux.Router assigned a root in one body": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

var assignedRoot *mux.Router

func boot() {
	assignedRoot = mux.NewRouter()
	assignedRoot.HandleFunc("/in-the-assigning-body", nil)
}

func R(param *mux.Router) {
	assignedRoot.HandleFunc("/elsewhere", nil)
	param.HandleFunc("/control", nil)
}
`},
			// BOTH must be reported, and the second one is the point. A name
			// assigned in a body is UNKNOWN, and it has to be unknown in the
			// body that assigns it too — otherwise the same name answers
			// differently in two places, which is the shape the inversion
			// exists to remove. This is `globalRouter` in
			// platform/agent/run.go, reduced.
			mustNot:  []string{"/in-the-assigning-body", "/elsewhere"},
			mustHave: []string{"/control"}, unresolved: 2},

		// An unrelated local `:=` of the SAME NAME must not poison the
		// package-level declaration. `assignedInBody` was keyed by name across
		// the whole package and recorded every AssignStmt including `:=` — but
		// a `:=` creates a NEW binding and says nothing about the package-level
		// name it happens to share a spelling with. Over-poisoning, the safe
		// direction, and still wrong: it cost a real route its prefix.
		"an unrelated local of the same name as a package-level subrouter": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

var rootR = mux.NewRouter()
var shared = rootR.PathPrefix("/pkg").Subrouter()

func other() *mux.Router { return nil }

func Unrelated() {
	shared := other()
	shared.HandleFunc("/local", nil)
}

func R() { shared.HandleFunc("/real", nil) }
`},
			// /local stays reported — that local IS unprovable. /pkg/real must
			// resolve: nothing about the package-level `shared` changed.
			mustNot:  []string{"/local", "/pkg/local"},
			mustHave: []string{"/pkg/real"}, unresolved: 1},

		// A local root shadowing a package-level name that IS pending. The
		// local is proved by rule (b) — `mux.NewRouter()` is the one
		// expression that proves a plain router — whatever the package-level
		// name of the same spelling is doing.
		"a local root shadowing a pending package-level subrouter": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

var rootR = mux.NewRouter()
var sub = rootR.PathPrefix("/pkg").Subrouter()

func other() *mux.Router { return nil }

func swap() { sub = other() }

func Local() {
	sub := mux.NewRouter()
	sub.HandleFunc("/own-root", nil)
}
`},
			mustHave: []string{"/own-root"}, unresolved: 0},

		// The POSITIVE side of the rule, so the inversion cannot pass by
		// reporting everything: all four proven shapes must still resolve.
		"the four proven shapes still resolve": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

var pkgRoot = mux.NewRouter()
var pkgSub = pkgRoot.PathPrefix("/pkg").Subrouter()

func R(param *mux.Router) {
	param.HandleFunc("/a-param", nil)

	local := mux.NewRouter()
	local.HandleFunc("/b-local-root", nil)

	var localVar = mux.NewRouter()
	localVar.HandleFunc("/b-local-var-root", nil)

	child := param.PathPrefix("/b").Subrouter()
	child.HandleFunc("/b-chain", nil)

	pkgSub.HandleFunc("/c-package", nil)

	param.PathPrefix("/d").Subrouter().HandleFunc("/d-immediate", nil)
}
`},
			mustHave: []string{"/a-param", "/b-local-root", "/b-local-var-root",
				"/b/b-chain", "/pkg/c-package", "/d/d-immediate"},
			unresolved: 0},
	} {
		t.Run(name, func(t *testing.T) {
			root := writeTree(t, tc.files)
			d, err := Derive(root, []string{"svc"})
			if err != nil {
				t.Fatal(err)
			}
			got := d.Patterns()
			for _, bad := range tc.mustNot {
				if slices.Contains(got, bad) {
					t.Errorf("%s: derived %q. A receiver this scanner cannot prove is a "+
						"router must be REPORTED, not priced from the root — pricing it "+
						"invents a URL the server does not serve, and an invented URL is "+
						"the one failure a census cannot recover from", name, bad)
				}
			}
			for _, want := range tc.mustHave {
				if !slices.Contains(got, want) {
					t.Errorf("%s: did not derive %q. The inversion must refuse the "+
						"unprovable shapes WITHOUT refusing the proven ones; a scanner "+
						"that reports everything passes every mustNot above and is "+
						"useless", name, want)
				}
			}
			if len(d.Unresolved()) != tc.unresolved {
				t.Errorf("%s: expected exactly %d unresolved site(s), got %d: %+v. Exact, "+
					"because 'at least one' is satisfied by a scanner that resolved "+
					"nothing", name, tc.unresolved, len(d.Unresolved()), d.Unresolved())
			}
		})
	}
}

// TestCrossPackagePoisonIsWrittenUnderThePackageQualifiedKey pins the two
// writes at the END of resolveConsts that nothing else reached.
//
// Every declaration is stored under TWO keys — the directory-scoped one a
// same-package reference reads, and the package-qualified one `paths.P` reads —
// and the two poison loops write BOTH. Deleting either package-qualified write
// left the whole package green: the same-package fixtures never look up a
// `pkg.Name` key, and the cross-package fixtures all resolve cleanly, so no
// existing case ever asks what a POISONED name looks like from another package.
// The consequence of the gap is the worst kind: the consumer keeps the value
// that was committed before the poison landed, and reports a confident path
// that the tree does not serve.
//
// The package-qualified key is the FALLBACK the resolver uses when an import
// path does not land on a directory it scanned — which is what two same-named
// packages in different directories produce. So the first case below declares
// `paths` twice, once readable and once not: the readable side commits, and
// only the pkg-qualified poison can take it back. The second case is the
// transitive pass, where a name derived from a poisoned one must be revisited
// under both of its keys.
func TestCrossPackagePoisonIsWrittenUnderThePackageQualifiedKey(t *testing.T) {
	consumer := `package svc

import (
	"net/http"

	"example/pkg/paths"

	"github.com/gorilla/mux"
)

func R(r *mux.Router, h http.HandlerFunc) {
	r.HandleFunc(paths.P, h)
	r.HandleFunc(paths.Q, h)
}
`
	for name, tc := range map[string]struct {
		files   map[string]string
		mustNot []string
		// control is a path in the SAME cross-package reference set that must
		// still resolve, so a scanner that resolved nothing cannot pass.
		control string
	}{
		// The UNREADABLE-declaration poison, reached through the fallback:
		// TWO packages named `paths`, one declaring P readably and the other
		// not. The readable one commits; nothing else ever takes it back.
		"an unreadable declaration in a same-named package": {
			files: map[string]string{
				"pkg/paths/paths.go": "package paths\n\n" +
					"const P = \"/api/v1/one\"\nconst Q = \"/api/v1/q\"\n",
				"other/paths/paths.go": "package paths\n\nimport \"os\"\n\n" +
					"var P = os.Getenv(\"AXONFLOW_P\")\n",
				"svc/r.go": consumer,
			},
			mustNot: []string{"/api/v1/one"}, control: "/api/v1/q"},

		// The TRANSITIVE poison. `Q = Base + "/q"` commits in the round Base
		// becomes readable; Base is only disqualified afterwards, by its
		// unreadable twin. The propagation pass is what revisits Q — and it
		// must revisit BOTH of Q's keys.
		"a name derived from a poisoned one": {
			files: map[string]string{
				"pkg/paths/ent.go": "//go:build enterprise\n\npackage paths\n\n" +
					"const Base = \"/api/v1\"\n",
				"pkg/paths/comm.go": "//go:build !enterprise\n\npackage paths\n\n" +
					"import \"os\"\n\nvar Base = os.Getenv(\"AXONFLOW_BASE\")\n",
				"pkg/paths/paths.go": "package paths\n\nconst P = \"/api/v1/plain\"\n" +
					"const Q = Base + \"/derived\"\n",
				"svc/r.go": consumer,
			},
			mustNot: []string{"/api/v1/derived"}, control: "/api/v1/plain"},
	} {
		t.Run(name, func(t *testing.T) {
			root := writeTree(t, tc.files)
			d, err := Derive(root, []string{"pkg", "other", "svc"})
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range d.Patterns() {
				for _, bad := range tc.mustNot {
					if p == bad {
						t.Errorf("derived %q from a package-qualified reference to a POISONED "+
							"name; the value committed before the poison landed survived under "+
							"the pkg.Name key", p)
					}
				}
			}
			// The positive control, in the same command as the negative one: a
			// clean cross-package constant in the SAME package still resolves,
			// so an empty Patterns() cannot pass this test by accident.
			if !slices.Contains(d.Patterns(), tc.control) {
				t.Errorf("control %q did not resolve, so the negative assertion above is "+
					"vacuous — a scanner that read nothing would pass it; patterns=%v",
					tc.control, d.Patterns())
			}
			if len(d.Unresolved()) == 0 {
				t.Errorf("a poisoned name was consumed and NOTHING was reported unresolved; "+
					"patterns=%v", d.Patterns())
			}
		})
	}
}

// TestARouterVariableIsPricedOnlyWhenProven is round 6's rule, stated as a
// table because the rule is one sentence and the shapes are many:
//
//	a package-level router variable is priced ONLY when its prefix is proven by
//	a single ValueSpec chain in the same package. Every other shape is UNKNOWN,
//	its uses poisoned and reported, and the poison is permanent.
//
// Each row names the shape and the path that must NOT appear. Six rounds of
// review found six ways to reach the root through a name that was not the
// root; the rule is what stops the seventh.
func TestARouterVariableIsPricedOnlyWhenProven(t *testing.T) {
	for name, tc := range map[string]struct {
		files      map[string]string
		mustNot    []string
		unresolved int
	}{
		// R6-1: declared with NO value, assigned inside init(). Nothing to
		// price from the declaration, and something elsewhere assigns it.
		"assigned in a function body": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

var rootR = mux.NewRouter()

var assignedLater *mux.Router

func init() { assignedLater = rootR.PathPrefix("/m").Subrouter() }

func R() { assignedLater.HandleFunc("/y", nil) }
`},
			mustNot: []string{"/y", "/m/y"}, unresolved: 1},

		// R6-7: a pending subrouter used at PACKAGE level, outside every
		// function body. The body walk and the package-level walk are two
		// separate passes and only one of them consulted `pending`, so this
		// registration was priced from the root while its sibling inside a
		// function was correctly reported.
		"a pending subrouter used in a package-level initialiser": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

var rootR = mux.NewRouter()

var later *mux.Router

func init() { later = rootR.PathPrefix("/m").Subrouter() }

var _ = later.HandleFunc("/pkglevel", nil)

func R() { rootR.HandleFunc("/control", nil) }
`},
			mustNot: []string{"/pkglevel", "/m/pkglevel"}, unresolved: 1},

		// R6-2: a child declared BETWEEN two twins. The sentinel used to
		// toggle per round, so the child could be priced off whichever side
		// happened to be current.
		"a child between two build-tag twins": {
			files: map[string]string{
				"svc/a.go": "//go:build enterprise\n\npackage svc\n\nvar twin = rootR.PathPrefix(\"/ent\").Subrouter()\n",
				"svc/m.go": "package svc\n\nvar child = twin.PathPrefix(\"/c\").Subrouter()\n",
				"svc/z.go": "//go:build !enterprise\n\npackage svc\n\nvar twin = rootR.PathPrefix(\"/comm\").Subrouter()\n",
				"svc/r.go": `package svc

import "github.com/gorilla/mux"

var rootR = mux.NewRouter()

func R() { child.HandleFunc("/x", nil) }
`},
			mustNot: []string{"/ent/c/x", "/comm/c/x", "/c/x", "/x"}, unresolved: 2},

		// A twin whose other side is not a subrouter at all never reached the
		// comparison, so it was priced off the one side that was.
		"a twin whose other side is a plain router": {
			files: map[string]string{
				"svc/a.go": "//go:build enterprise\n\npackage svc\n\nvar twin = rootR.PathPrefix(\"/ent\").Subrouter()\n",
				"svc/z.go": "//go:build !enterprise\n\npackage svc\n\nimport \"github.com/gorilla/mux\"\n\nvar twin = mux.NewRouter()\n",
				"svc/r.go": `package svc

import "github.com/gorilla/mux"

var rootR = mux.NewRouter()

func R() { twin.HandleFunc("/x", nil) }
`},
			mustNot: []string{"/ent/x", "/x"}, unresolved: 1},

		// An unfollowable home HEADING a chain: the chain was priced from the
		// root because only the direct registration was poisoned.
		"a chain built on an unfollowable home": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

type srv struct{ sub *mux.Router }

func (s *srv) F(r *mux.Router) {
	s.sub = r.PathPrefix("/hidden").Subrouter()
	deep := s.sub.PathPrefix("/p").Subrouter()
	deep.HandleFunc("/x", nil)
}
`},
			mustNot: []string{"/p/x", "/hidden/p/x", "/x"}, unresolved: 3},

		// Subrouter() on something that is not a chain at all. Returning "not
		// a subrouter" left the name unlearned, and an unlearned name is
		// priced from the root.
		"Subrouter on a call result and on a Route": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

func f() *mux.Router { return nil }

func F(root *mux.Router) {
	a := f().Subrouter()
	a.HandleFunc("/a", nil)
	rt := root.PathPrefix("/rt")
	b := rt.Subrouter()
	b.HandleFunc("/b", nil)
}
`},
			mustNot: []string{"/a", "/b", "/rt/b"}, unresolved: 2},

		// An ALIAS of a subrouter. Carrying the prefix across would be a new
		// resolution path; the rule says report instead.
		"an alias of a known subrouter": {
			files: map[string]string{"svc/r.go": `package svc

import "github.com/gorilla/mux"

func F(root *mux.Router) {
	a := root.PathPrefix("/a").Subrouter()
	var b = a
	b.HandleFunc("/x", nil)
}
`},
			mustNot: []string{"/x", "/a/x"}, unresolved: 1},
	} {
		t.Run(name, func(t *testing.T) {
			root := writeTree(t, tc.files)
			d, err := Derive(root, []string{"svc"})
			if err != nil {
				t.Fatal(err)
			}
			found := map[string]bool{}
			for _, p := range d.Patterns() {
				found[p] = true
			}
			for _, bad := range tc.mustNot {
				if found[bad] {
					t.Errorf("%s: resolved %s. A router variable whose prefix is not proven "+
						"by a single ValueSpec chain in its own package is UNKNOWN, and "+
						"pricing it from the root invents a path no server serves",
						name, bad)
				}
			}
			if got := len(d.Unresolved()); got != tc.unresolved {
				t.Errorf("%s: expected exactly %d reported site(s), got %d: %+v. Fewer "+
					"means something was dropped silently; more means a readable shape "+
					"is being refused", name, tc.unresolved, got, d.Unresolved())
			}
		})
	}
}
