// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestPlaneModelMatchesTheCensus is this module's half of the pin that binds
// the plane model to the tree it claims to describe.
//
// The other half is TestLegacyCallSiteCensusIsComplete in the MAIN module,
// which proves legacy_call_sites.tsv names exactly the call sites that exist.
// This one proves the plane model says nothing the census does not support.
//
// Between them: a plane cannot be invented (it would have no census rows), a
// plane cannot go missing (the census rows would belong to no plane), and no
// plane can claim a substrate, a phase or a posture the call sites do not have.
// AllPlanes is the shadow gate's denominator, so each of those is the
// difference between measuring an enforcement surface and reporting coverage of
// one that does not exist.
func TestPlaneModelMatchesTheCensus(t *testing.T) {
	rows := readTSV(t, "legacy_call_sites.tsv",
		[]string{"plane", "evaluator", "file", "function", "passes_action_overrides", "edition", "default_posture", "gate"})
	if len(rows) == 0 {
		t.Fatal("legacy_call_sites.tsv is empty; an empty census supports any model at all")
	}

	type siteFacts struct {
		evaluators map[string]bool
		overrides  map[string]bool // evaluator -> any call site passes overrides
		files      []string
	}
	byPlane := map[Plane]*siteFacts{}
	for _, r := range rows {
		// The edition column says which build carries the file. Its TRUTH is
		// pinned by platform/shared/policy's TestLegacyCallSiteCensusIsComplete
		// against the file's real build constraint; here only its vocabulary
		// is checked, so a row cannot carry a third value both tests ignore.
		switch r["edition"] {
		case "community", "enterprise":
		default:
			t.Fatalf("legacy_call_sites.tsv: row for %s %s has edition %q, want community or enterprise", r["file"], r["function"], r["edition"])
		}
		p := Plane(r["plane"])
		if byPlane[p] == nil {
			byPlane[p] = &siteFacts{evaluators: map[string]bool{}, overrides: map[string]bool{}}
		}
		f := byPlane[p]
		f.evaluators[r["evaluator"]] = true
		if r["passes_action_overrides"] == "yes" {
			f.overrides[r["evaluator"]] = true
		}
		f.files = append(f.files, r["file"]+" "+r["function"])
	}

	// Every census plane is modelled, and every modelled plane is in the
	// census. Both directions, because the two failures are opposite and both
	// are silent.
	for p := range byPlane {
		if _, ok := planeSpecs[p]; !ok {
			t.Fatalf("the census records call sites for plane %q and planeSpecs has no entry for it: %v",
				p, byPlane[p].files)
		}
	}
	for p := range planeSpecs {
		if _, ok := byPlane[p]; !ok {
			t.Fatalf("planeSpecs models plane %q and the census records no call site for it; "+
				"a plane with no evaluation behind it reads as coverage of something that does not exist", p)
		}
	}

	for _, p := range AllPlanes() {
		spec := MustSpecFor(p)
		f := byPlane[p]

		staticSite := f.evaluators["EvaluateRequest"] || f.evaluators["EvaluateResponse"]
		// The dynamic substrate is reached through the legacy engine's evaluator or,
		// on a plane cut over to the anchored engine, through the dynamic matcher
		// running as a fact producer (#4254).
		dynamicSite := f.evaluators["EvaluateDynamicPolicies"] || f.evaluators[EvaluatorDynamicFacts]

		claimsStatic, claimsDynamic := false, false
		for _, s := range spec.Substrates {
			switch s {
			case SubstrateStatic:
				claimsStatic = true
			case SubstrateDynamic:
				claimsDynamic = true
			}
		}
		if claimsStatic != staticSite {
			t.Fatalf("plane %q claims static=%t and the census has a static-engine call site=%t (%v)",
				p, claimsStatic, staticSite, f.files)
		}
		if claimsDynamic != dynamicSite {
			t.Fatalf("plane %q claims dynamic=%t and the census has an EvaluateDynamicPolicies or Produce (dynamic fact producer) call site=%t (%v)",
				p, claimsDynamic, dynamicSite, f.files)
		}

		// A plane that evaluates a phase must have a call site for it.
		if spec.EvaluatesPhase(PhaseResponse) && !f.evaluators["EvaluateResponse"] {
			t.Fatalf("plane %q claims the response phase and the census has no EvaluateResponse call site (%v)", p, f.files)
		}
		if spec.EvaluatesPhase(PhaseRequest) && !f.evaluators["EvaluateRequest"] {
			t.Fatalf("plane %q claims the request phase and the census has no request-side call site (%v)", p, f.files)
		}
		if f.evaluators["EvaluateResponse"] && !spec.EvaluatesPhase(PhaseResponse) {
			t.Fatalf("plane %q has an EvaluateResponse call site and does not model the response phase (%v)", p, f.files)
		}

		// The organization override map. A plane claiming it must have a call site that
		// passes ActionOverrides; a plane denying it must either have none, or
		// declare a ForcedAction - which is the cowork case, where the map
		// passed is the handler's own and not the organization's overrides.
		anyOverrides := false
		for _, v := range f.overrides {
			if v {
				anyOverrides = true
			}
		}
		if spec.PassesOrgOverrides && !anyOverrides {
			t.Fatalf("plane %q claims an organization override displaces its actions and no census call site passes ActionOverrides (%v)", p, f.files)
		}
		if !spec.PassesOrgOverrides && anyOverrides && spec.ForcedAction == "" {
			t.Fatalf("plane %q denies passing the override map, passes ActionOverrides at a census call site, and declares no ForcedAction; "+
				"one of the three is wrong and a plane whose actions are displaced by something the model does not name "+
				"attributes the displacement to the compiler (%v)", p, f.files)
		}
	}

	// Anti-vacuity, derived: the census must actually distinguish the axes it
	// is being used to pin. A census in which every plane looked the same would
	// agree with any model.
	var planes []string
	staticPlanes, dynamicPlanes, overridePlanes, retiredReadPlanes := 0, 0, 0, 0
	for _, p := range AllPlanes() {
		planes = append(planes, string(p))
		spec := MustSpecFor(p)
		for _, s := range spec.Substrates {
			if s == SubstrateStatic {
				staticPlanes++
			} else {
				dynamicPlanes++
			}
		}
		if spec.PassesOrgOverrides {
			overridePlanes++
		}
		if spec.EnforcesRetiredTierPassRead {
			retiredReadPlanes++
			if p != PlaneProxyRequest {
				t.Errorf("plane %q keeps the retired tier pass's read of the stored action column; only /api/request's retired second pass read it (#4253)", p)
			}
		}
	}
	sort.Strings(planes)
	if staticPlanes == 0 || dynamicPlanes == 0 {
		t.Fatalf("the model has %d static and %d dynamic plane claims; both substrates must appear or the substrate axis is untested",
			staticPlanes, dynamicPlanes)
	}
	if overridePlanes == 0 || overridePlanes == len(planes) {
		t.Fatalf("%d of %d planes pass the override map; if every plane or none does, the axis pins nothing", overridePlanes, len(planes))
	}
	if retiredReadPlanes != 1 {
		t.Fatalf("%d planes enforce a system row's stored block; exactly proxy_request does (#4253)", retiredReadPlanes)
	}
	t.Logf("plane model agrees with the census over %d plane(s): %s", len(planes), strings.Join(planes, ", "))
}

// TestUnimplementedPlanesAreRecordedNotModelled pins the third option between
// inventing a plane and omitting one.
func TestUnimplementedPlanesAreRecordedNotModelled(t *testing.T) {
	if len(UnimplementedPlanes) == 0 {
		t.Skip("no plane is currently recorded as unimplemented")
	}
	rows := readTSV(t, "legacy_call_sites.tsv",
		[]string{"plane", "evaluator", "file", "function", "passes_action_overrides", "edition", "default_posture", "gate"})
	inCensus := map[string]bool{}
	for _, r := range rows {
		inCensus[r["plane"]] = true
	}
	for p, why := range UnimplementedPlanes {
		if _, modelled := planeSpecs[p]; modelled {
			t.Fatalf("plane %q is recorded as unimplemented AND modelled in planeSpecs; it would be compiled for and counted", p)
		}
		if inCensus[string(p)] {
			t.Fatalf("plane %q is recorded as unimplemented and the census has call sites for it; one of the two is stale", p)
		}
		if len(why) < 40 {
			t.Fatalf("plane %q is recorded as unimplemented with a %d-character reason; a bare entry is a claim nobody can check", p, len(why))
		}
	}
}

// TestGatedPlanesMatchTheCallSiteCensus binds PlanesGatedUnderDefaultPosture to
// the column that carries the same fact, in BOTH directions.
//
// The failure it exists for is not a wrong entry, it is a missing one. A plane
// whose every call site is gated and which nobody listed reads, in every
// instrument downstream, as a watched plane with no traffic - and that is
// exactly how the map plane's empty window survived a full observation window
// being read as healthy. So "every gated plane is declared" is the direction
// that matters, and "every declared plane is gated" is here because a
// declaration that outlives its gate silences a plane that has since become
// measurable, which is the same defect pointing the other way.
func TestGatedPlanesMatchTheCallSiteCensus(t *testing.T) {
	rows := readTSV(t, "legacy_call_sites.tsv",
		[]string{"plane", "evaluator", "file", "function", "passes_action_overrides", "edition", "default_posture", "gate"})

	// ANTI-VACUITY. A reader that stopped matching returns no rows, every
	// `allGated` below is then vacuously true over an empty set, and the test
	// reports a fully consistent model derived from nothing.
	if len(rows) == 0 {
		t.Fatal("the call-site census is empty; an empty census makes every claim below vacuously true")
	}

	// THE SAME CLASSIFIER THE ANTI-VACUITY CONTROL BELOW EXERCISES.
	gatedSites, openSites := classifyPostureRows(t, rows)

	// THE ANTI-VACUITY CONTROL RUNS OVER A SYNTHETIC FIXTURE, NOT OVER THE LIVE
	// TABLE (R3 round 1, F8).
	//
	// The first version required the live census to contain at least one gated
	// row and one reachable row. `map` is the only gated row in the table, and
	// its entry is DESIGNED TO EXPIRE - its REVISIT WHEN says so. So on the day
	// #3555 is actually fixed and the row flips to `reachable`, this test would
	// have gone red with "one branch of this test examined nothing", and the
	// cheapest way out would have been deleting the floor: a guard control that
	// reds the day the row it reads is honoured, which is the exact class W0-E
	// paid for on #3840.
	//
	// The classifier is exercised over a fixture that can never expire, and the
	// live table is held only to the direction checks below.
	// AND IT RUNS THE REAL CLASSIFIER. An earlier version of this control had a
	// local copy of the switch, so it certified a function the live path never
	// calls - and the two already disagreed on the unknown-value case. A
	// re-implementation that agrees with the real thing is indistinguishable
	// from a correct one.
	fixtureGated, fixtureOpen := classifyPostureRows(t, []map[string]string{
		{"plane": "fixture_gated", "file": "f.go", "function": "F",
			"default_posture": "gated", "gate": "FIXTURE_GATE_VAR"},
		{"plane": "fixture_open", "file": "g.go", "function": "G",
			"default_posture": "reachable", "gate": "-"},
	})
	if len(fixtureGated) != 1 || len(fixtureOpen) != 1 {
		t.Fatalf("the classifier put %d plane(s) in the gated bucket and %d in the reachable one for a "+
			"two-row fixture holding exactly one of each; the classification below is not working, so "+
			"every direction check would be a statement about nothing",
			len(fixtureGated), len(fixtureOpen))
	}

	// And the live table must have been READ. This floor cannot expire: rows
	// are only ever added.
	if len(gatedSites)+len(openSites) == 0 {
		t.Fatal("the live census classified no plane at all; the reader is broken, not the model")
	}

	for p := range planeSpecs {
		name := string(p)
		allGated := len(gatedSites[name]) > 0 && len(openSites[name]) == 0
		_, declared := PlanesGatedUnderDefaultPosture[p]

		if allGated && !declared {
			t.Errorf("every call site for plane %q is gated (%v) and PlanesGatedUnderDefaultPosture does "+
				"not declare it.\n\n"+
				"No default-posture deployment can produce an observation for this plane, so its ADR-065 "+
				"gate 18 denominator is permanently zero - and metrics.go pre-creates that zero, which "+
				"makes it indistinguishable from a watched plane awaiting traffic. Declare it, with a "+
				"REVISIT WHEN naming a queryable observable, or make a site reachable.",
				name, gatedSites[name])
		}
		if declared && !allGated {
			t.Errorf("PlanesGatedUnderDefaultPosture declares plane %q and it has reachable call site(s) "+
				"%v; the declaration is stale and is suppressing a plane that can now accumulate a window",
				name, openSites[name])
		}
	}

	for p, why := range PlanesGatedUnderDefaultPosture {
		if _, modelled := planeSpecs[p]; !modelled {
			t.Errorf("PlanesGatedUnderDefaultPosture declares plane %q, which planeSpecs does not model; "+
				"a gate on a plane that does not exist is an entry nothing can retire", p)
		}
		// The reason must carry its own retirement condition. A gap with no
		// stated way to notice it has closed is an exemption that outlives it.
		if !strings.Contains(why, "REVISIT WHEN") {
			t.Errorf("PlanesGatedUnderDefaultPosture[%q] states no REVISIT WHEN condition; a deliberate "+
				"gap needs a named observable that says when it has closed", p)
		}
		if len(why) < 40 {
			t.Errorf("PlanesGatedUnderDefaultPosture[%q] has a %d-character reason; a bare entry is a "+
				"claim nobody can check", p, len(why))
		}
	}
}

// TestEditionGatedPlanesMatchTheCallSiteCensus is the third direction, and it
// exists because the second one could not see this class at all (R3 round 1).
//
// TestGatedPlanesMatchTheCallSiteCensus reads default_posture, which is a
// statement about CONFIGURATION on a deployment of the row's own edition. A
// plane whose every call site is enterprise-tagged is perfectly reachable there
// and unreachable on a community build for a reason no configuration can
// change - so it is `reachable` in that column, correctly, and the config
// census passes while the plane sits on a community stack reporting
// mode=shadow, compared=0.
//
// The edition column already carries the fact. Nothing was reading it for this.
func TestEditionGatedPlanesMatchTheCallSiteCensus(t *testing.T) {
	rows := readTSV(t, "legacy_call_sites.tsv",
		[]string{"plane", "evaluator", "file", "function", "passes_action_overrides", "edition", "default_posture", "gate"})
	if len(rows) == 0 {
		t.Fatal("the call-site census is empty; every claim below would be vacuously true")
	}

	enterpriseOnly := map[string][]string{}
	community := map[string][]string{}
	for _, r := range rows {
		site := r["file"] + " " + r["function"]
		if r["edition"] == "enterprise" {
			enterpriseOnly[r["plane"]] = append(enterpriseOnly[r["plane"]], site)
		} else {
			community[r["plane"]] = append(community[r["plane"]], site)
		}
	}

	// ANTI-VACUITY, and it must exercise BOTH editions or one branch below
	// examined nothing. Deliberately NOT anchored to a specific plane: the row
	// that makes this non-empty is a live one and rows expire.
	if len(enterpriseOnly) == 0 || len(community) == 0 {
		t.Fatalf("the census records %d plane(s) with an enterprise-tagged site and %d with a "+
			"community one; both must be non-empty or this test examined nothing",
			len(enterpriseOnly), len(community))
	}

	for p := range planeSpecs {
		name := string(p)
		allEnterprise := len(enterpriseOnly[name]) > 0 && len(community[name]) == 0
		_, declared := PlanesGatedByEdition[p]

		if allEnterprise && !declared {
			t.Errorf("every call site for plane %q is enterprise-tagged (%v) and "+
				"PlanesGatedByEdition does not declare it.\n\n"+
				"planeSpecs is not build-tagged, so a COMMUNITY binary still models this plane "+
				"although its code is not in the binary. Declare it.", name, enterpriseOnly[name])
		}
		if declared && !allEnterprise {
			t.Errorf("PlanesGatedByEdition declares plane %q and it has community call site(s) %v; "+
				"the declaration is stale and is suppressing a plane a community build CAN reach",
				name, community[name])
		}
	}

	for p, why := range PlanesGatedByEdition {
		if _, modelled := planeSpecs[p]; !modelled {
			t.Errorf("PlanesGatedByEdition declares plane %q, which planeSpecs does not model", p)
		}
		if !strings.Contains(why, "REVISIT WHEN") {
			t.Errorf("PlanesGatedByEdition[%q] states no REVISIT WHEN condition; a deliberate gap "+
				"needs a named observable that says when it has closed", p)
		}
		if len(why) < 40 {
			t.Errorf("PlanesGatedByEdition[%q] has a %d-character reason; a bare entry is a claim "+
				"nobody can check", p, len(why))
		}
	}
}

// TestAGatedRowNamesAnEnvironmentVariableTheTreeActuallyReads is the
// derivation the two new columns were missing (R3 round 1, F5).
//
// # WHY THIS COLUMN NEEDED ONE MORE THAN THE OTHERS
//
// Every other column in legacy_call_sites.tsv is proved against the tree on
// every run: plane / evaluator / file / function and passes_action_overrides by
// AST scan, and `edition` against the file's real build constraint. The two
// columns this change added were verified against nothing - they were bound
// only to PlanesGatedUnderDefaultPosture, which is to say to another hand-typed
// record of the same claim. Two hand-typed records agreeing is not evidence.
//
// A full derivation of "is this call site reachable under the default posture"
// is not available to a static census - reachability runs through a constructor,
// an interface and two environment reads. What IS checkable, and is the half
// that would have caught a fabricated entry, is that every environment variable
// a `gated` row names is one this tree actually reads. A gate nobody reads is a
// gate that does not exist, and the census's own rule is that a gate nobody can
// name is a claim nobody can check.
//
// It deliberately does NOT try to prove the gate governs THAT call site. That
// would be a call-graph claim, and asserting more than the mechanism supports
// is the failure this whole PR is about.
func TestAGatedRowNamesAnEnvironmentVariableTheTreeActuallyReads(t *testing.T) {
	rows := readTSV(t, "legacy_call_sites.tsv",
		[]string{"plane", "evaluator", "file", "function", "passes_action_overrides", "edition", "default_posture", "gate"})
	if len(rows) == 0 {
		t.Fatal("the call-site census is empty; every claim below would be vacuously true")
	}

	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}

	// Collect every environment variable name the platform tree reads. From the
	// SOURCE, so a variable that stops being read fails here rather than
	// leaving a gate that reads as live.
	// FROM THE AST, NOT A REGEX OVER BYTES (R3 round 3).
	//
	// The first version scanned raw file bytes, so `os.Getenv("X")` inside a
	// COMMENT counted as the tree reading X. That is not hypothetical here:
	// platform/shared/deploymode/deploymode.go documents the read in prose, so
	// half the evidence for the only gated row today was a comment - and a
	// fabricated gate could be validated by adding a file whose sole content
	// mentions it. Proven by plant. Parsing without ParseComments makes the
	// question "does this tree CALL Getenv with this literal", which is the
	// question the row is asserting.
	read := map[string]bool{}
	filesScanned := 0
	for _, sub := range []string{"platform", "ee"} {
		_ = filepath.WalkDir(filepath.Join(root, sub), func(path string, d fs.DirEntry, err error) error {
			// _test.go IS EXCLUDED. "A gate nobody reads fails" has to mean
			// nobody in the shipped binaries, not nobody-but-a-test: a gate
			// read only by a harness governs nothing on a deployment.
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") ||
				strings.HasSuffix(path, "_test.go") {
				return nil //nolint:nilerr // an unreadable subtree is covered by the floor below
			}
			fset := token.NewFileSet()
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil //nolint:nilerr // a file that does not parse is covered by the floor below
			}
			filesScanned++
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) != 1 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Getenv" {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "os" {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if v, uerr := strconv.Unquote(lit.Value); uerr == nil {
					read[v] = true
				}
				return true
			})
			return nil
		})
	}

	// ANTI-VACUITY, both halves. A walk that found no files, or a pattern that
	// matched no reads, would report every gate live.
	if filesScanned < 100 {
		t.Fatalf("the scan read %d Go file(s) under %s; the walk is broken, not the tree, and a "+
			"broken walk reports every gate as unread", filesScanned, root)
	}
	if len(read) < 20 {
		t.Fatalf("the scan found %d environment variable read(s) in a tree that configures itself "+
			"almost entirely through them; the pattern has stopped matching", len(read))
	}
	// And the pattern must be able to return a POSITIVE for something we know
	// is there, or a gate could pass by the scan silently under-matching.
	if !read["AXONFLOW_HITL_ENABLED"] {
		t.Fatalf("the scan did not find AXONFLOW_HITL_ENABLED, which run.go reads to decide whether " +
			"the MAP checker is built; the extraction is under-matching and every gate below would " +
			"be judged against an incomplete set")
	}

	envToken := regexp.MustCompile(`\b[A-Z][A-Z0-9_]{3,}\b`)
	for _, r := range rows {
		if r["default_posture"] != "gated" {
			continue
		}
		site := r["file"] + " " + r["function"]
		names := envToken.FindAllString(r["gate"], -1)
		if len(names) == 0 {
			t.Errorf("%s is gated and its gate %q names no environment variable. If the gate is not "+
				"an environment variable it is a different KIND of gate - an edition, say, which "+
				"PlanesGatedByEdition models separately - and this row should say so rather than "+
				"carrying prose nothing can check.", site, r["gate"])
			continue
		}
		for _, name := range names {
			// Literals a gate expression may contain that are not variables.
			// AND / OR / NOT are deliberately absent: the token pattern needs
			// four characters, so they can never reach here, and listing them
			// would describe a filter that does not run - the same
			// comment-outlives-the-code class this file guards elsewhere.
			switch name {
			case "TRUE", "FALSE", "NULL", "NONE":
				continue
			}
			if !read[name] {
				t.Errorf("%s is gated on %q, and no os.Getenv(%q) exists anywhere under platform/ or "+
					"ee/. Either the gate was renamed - in which case this row now describes a "+
					"variable nobody reads, and the plane's real reachability is unrecorded - or the "+
					"entry was written from memory.", site, name, name)
			}
		}
	}
	// THE EXTRACTOR'S OWN CONTROL RUNS OVER A SYNTHETIC ROW, NOT THE LIVE SET
	// (R3 round 2).
	//
	// The first version required the live gated set to name at least one
	// checkable variable. `map` is its only member and its REVISIT WHEN says it
	// is designed to expire, so on the day #3555 succeeds this floor would have
	// reddened - with a message misdiagnosing the cause ("gated by something
	// other than an environment variable" when the real state is "no gated rows
	// exist"), pointing the next engineer at the wrong repair and making
	// deletion the cheapest exit. That is the same class the sibling census was
	// moved off a live row to avoid, reintroduced one test over.
	//
	// The live table is held only to the direction check above; the extractor is
	// exercised here, on a row that cannot expire.
	fixtureNames := envToken.FindAllString("PLANTED_FIXTURE_VAR=true AND OTHER_FIXTURE_VAR not set", -1)
	if len(fixtureNames) != 2 {
		t.Fatalf("the gate tokeniser found %v in a fixture naming exactly two variables; it has "+
			"stopped matching, and every live row above was judged by it", fixtureNames)
	}
	if read["PLANTED_FIXTURE_VAR"] {
		t.Fatal("the environment scan claims the tree reads PLANTED_FIXTURE_VAR, which exists only " +
			"in this fixture; the membership test is matching something it should not")
	}
}

// classifyPostureRows is THE classifier both the live table and the
// anti-vacuity fixture go through.
//
// It is a function rather than an inline switch precisely so the control cannot
// certify a copy: an earlier version had one loop for the live rows and a
// second, subtly different one for the fixture.
func classifyPostureRows(t *testing.T, rows []map[string]string) (gated, open map[string][]string) {
	t.Helper()
	gated, open = map[string][]string{}, map[string][]string{}
	for _, r := range rows {
		site := r["file"] + " " + r["function"]
		switch r["default_posture"] {
		case "gated":
			if r["gate"] == "-" || strings.TrimSpace(r["gate"]) == "" {
				t.Errorf("%s is default_posture=gated with no gate named; a gate nobody can name is "+
					"a claim nobody can check or clear", site)
			}
			gated[r["plane"]] = append(gated[r["plane"]], site+" (gate: "+r["gate"]+")")
		case "reachable":
			if r["gate"] != "-" {
				t.Errorf("%s is default_posture=reachable and names gate %q; a reachable site has no "+
					"gate, so one of the two columns is wrong", site, r["gate"])
			}
			open[r["plane"]] = append(open[r["plane"]], site)
		default:
			// Errorf, not Fatalf: a sweep that mistyped ten rows should report
			// ten, not the first. A census exists to give the whole picture.
			t.Errorf("%s has default_posture=%q, want reachable or gated", site, r["default_posture"])
		}
	}
	return gated, open
}

// TestPlaneComponentsMatchTheCallSiteCensus derives plane ownership from the
// call-site table's `file` column and holds planeComponents to it.
//
// "Which binary can reach this plane" is a fact of the model that nothing
// else records. A hand-typed copy would drift from the
// tree the first time a call site moved between binaries, and the failure is
// silent in the dangerous direction: a component would go on reporting a plane
// watched that it cannot reach.
func TestPlaneComponentsMatchTheCallSiteCensus(t *testing.T) {
	rows := readTSV(t, "legacy_call_sites.tsv",
		[]string{"plane", "evaluator", "file", "function", "passes_action_overrides", "edition", "default_posture", "gate"})
	if len(rows) == 0 {
		t.Fatal("the call-site census is empty; every claim below would be vacuously true")
	}

	derived := map[Plane]map[string]bool{}
	for _, r := range rows {
		var component string
		switch {
		case strings.HasPrefix(r["file"], "platform/agent/"):
			component = ComponentAgent
		case strings.HasPrefix(r["file"], "platform/orchestrator/"):
			component = ComponentOrchestrator
		default:
			t.Errorf("call site %s is in neither platform/agent/ nor platform/orchestrator/. A third "+
				"binary holding a legacy call site needs a component constant and an entry here "+
				"rather than a silent default.", r["file"])
			continue
		}
		if derived[Plane(r["plane"])] == nil {
			derived[Plane(r["plane"])] = map[string]bool{}
		}
		derived[Plane(r["plane"])][component] = true
	}

	// ANTI-VACUITY, and it must see BOTH binaries: a prefix match that stopped
	// working would put every plane on one component and satisfy half the
	// checks below trivially.
	agents, orchestrators := 0, 0
	for _, comps := range derived {
		if comps[ComponentAgent] {
			agents++
		}
		if comps[ComponentOrchestrator] {
			orchestrators++
		}
	}
	if agents == 0 || orchestrators == 0 {
		t.Fatalf("the census derived %d agent-owned and %d orchestrator-owned plane(s); both must be "+
			"non-zero or the file-prefix extraction has stopped matching", agents, orchestrators)
	}

	for p := range planeSpecs {
		want := derived[p]
		got := map[string]bool{}
		for _, c := range ComponentsForPlane(p) {
			got[c] = true
		}
		if len(want) == 0 {
			t.Errorf("plane %q has no call site in the census, so no component holds it; "+
				"TestPlaneModelMatchesTheCensus should have caught this first", p)
			continue
		}
		for c := range want {
			if !got[c] {
				t.Errorf("the census puts a %q call site for plane %q and planeComponents does not "+
					"record it.\n\n"+
					"That component publishes mode=shadow for the plane and would be declared "+
					"UNREACHABLE for it at install - suppressing a vacuity alert for a plane it can "+
					"genuinely reach, which is the failure direction that hides a real empty window.",
					c, p)
			}
		}
		for c := range got {
			if !want[c] {
				t.Errorf("planeComponents records %q as holding plane %q and the census has no call "+
					"site there.\n\n"+
					"That component will NOT declare the plane unreachable, so it goes on reporting "+
					"mode=shadow with a pre-created zero for a plane it cannot reach - the exact "+
					"reading #3555 exists to end.", c, p)
			}
		}
	}
}
