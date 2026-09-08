// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
)

// THE DETECTOR CENSUS (#3786, epic #3549)
//
// One row per platform-shipped static detection row, classified into the two
// implementation classes the operator's 2026-09-06 boundary names:
//
//	(a) pattern     - the pattern IS data. A customer may add their own.
//	(b) algorithmic - a checksum, a context window or a jurisdiction rule.
//	                  Code with a version and a conformance case. A customer
//	                  controls where it applies, not what it computes.
//	(c) not_a_detector - the row inspects no content; it is a plain verdict
//	                  rule and becomes a grant, ceiling or requirement.
//
// WHERE THE CLASS COMES FROM, AND WHY IT IS NOT THE ROW'S NAME
//
// A row is (b) when the code that actually runs resolves a ValidatorFunc for
// it. That resolution is `PolicyLoader.getValidatorForPolicy`: token match on
// the policy id first (ValidatorForPolicyID), the category default second
// (GetValidatorForCategory). This test recomputes it from those two exported
// functions and compares, so a row cannot be classified by what it is called.
// `sys_pii_singapore_nric` sounds algorithmic and, on the community tree,
// is not - its category default is deliberately nil (#1076) and its policy-id
// token IS mapped, which only the code can tell you.
//
// The implementation site for a (b) row is likewise DERIVED:
// runtime.FuncForPC on the resolved function value yields the defining file
// and symbol. Nobody transcribes it, so it cannot drift from the tree.
//
// WHERE THE REST OF EACH ROW COMES FROM
//
// The row facts, the ADR-065 emit, the obligations and the disposition are
// read from `legacycompile`'s per-row Record against a REAL capture of a
// migrated database (scripts/legacy-policy-capture.sh). Nothing in this file
// re-derives a mapping the compiler already owns: the emit is a projection of
// the compiled policy's Authority, and the obligations are the compiled
// policy's own obligation types.
//
// WHY THE FIXTURE LIVES IN platform/decision/registry AND THIS TEST DOES NOT
//
// `platform/decision` is a separate Go module that does not - and must not -
// depend on `axonflow/platform`. The census fixture belongs beside the
// detector registry that W2-B builds (platform/decision/registry), but the
// class can only be derived where the detector implementations are visible,
// which is this module. Reading a decision-plane TSV from a test in
// platform/shared/policy is the pattern legacy_call_site_census_test.go
// already established for exactly this reason; this file follows it rather
// than introducing a second one.
//
// THE TEST IS A RATCHET, NOT A REPORT
//
// TestDetectorCensusMatchesTheMigratedDatabase is set equality in BOTH
// directions and refuses an empty census and an empty capture. A migration
// that seeds a detection row without censusing it is red; a census row whose
// database row was superseded is red. Both failures were planted and proven.

const (
	detectorCensusPath           = "../../decision/registry/detectors_census.tsv"
	detectorCensusSupersededPath = "../../decision/registry/detectors_census_superseded.tsv"
	postureLeversPath            = "../../decision/legacycompile/legacy_posture_levers.tsv"
	postureFoldPath              = "../../decision/registry/detection_posture_fold.tsv"
	callSitesPath                = "../../decision/legacycompile/legacy_call_sites.tsv"
)

// postureFoldColumns is the fold table's header, in order.
var postureFoldColumns = []string{"lever", "destination", "census_rows", "note"}

// patternImplSiteRe is the exact shape a class (a) row's impl_site must have.
var patternImplSiteRe = regexp.MustCompile(`^re2:sha256:[0-9a-f]{12}$`)

// detectorCensusColumns is the header, in order. The parse refuses a file
// whose header is not exactly this, because a reordered column would silently
// compare the wrong two fields.
var detectorCensusColumns = []string{
	"policy_id", "name", "category", "tier", "enabled",
	"class", "impl_site", "legacy_action", "severity",
	"adr065_emit", "obligations", "posture_lever",
	"disposition", "disposition_reasons", "planes", "validator_planes",
	"seed_migration", "exceptions",
}

var detectorCensusSupersededColumns = []string{
	"policy_id", "seeded_by", "superseded_by", "still_live", "tracking", "note",
}

// Class values.
const (
	classPattern      = "pattern"
	classAlgorithmic  = "algorithmic"
	classNotADetector = "not_a_detector"
)

// ADR-065 emit values, in the operator's vocabulary.
const (
	emitDeny     = "Deny"
	emitEscalate = "Escalate"
	emitSignal   = "Signal"
	emitNone     = "-"
)

type detectorCensusRow struct {
	PolicyID           string
	Name               string
	Category           string
	Tier               string
	Enabled            string
	Class              string
	ImplSite           string
	LegacyAction       string
	Severity           string
	Emit               string
	Obligations        string
	PostureLever       string
	Disposition        string
	DispositionReasons string
	Planes             string
	ValidatorPlanes    string
	SeedMigration      string
	Exceptions         string
}

func (r detectorCensusRow) fields() []string {
	return []string{
		r.PolicyID, r.Name, r.Category, r.Tier, r.Enabled,
		r.Class, r.ImplSite, r.LegacyAction, r.Severity,
		r.Emit, r.Obligations, r.PostureLever,
		r.Disposition, r.DispositionReasons, r.Planes, r.ValidatorPlanes,
		r.SeedMigration, r.Exceptions,
	}
}

func detectorCensusRowFrom(fields []string) detectorCensusRow {
	return detectorCensusRow{
		PolicyID: fields[0], Name: fields[1], Category: fields[2], Tier: fields[3], Enabled: fields[4],
		Class: fields[5], ImplSite: fields[6], LegacyAction: fields[7], Severity: fields[8],
		Emit: fields[9], Obligations: fields[10], PostureLever: fields[11],
		Disposition: fields[12], DispositionReasons: fields[13], Planes: fields[14],
		ValidatorPlanes: fields[15], SeedMigration: fields[16], Exceptions: fields[17],
	}
}

// readCensusTSV parses a tab-separated fixture with a required header, skipping
// comment lines. It refuses a row with the wrong field count rather than
// padding, because a short row would compare an empty string against a real
// value and pass.
func readCensusTSV(path string, want []string) ([]([]string), error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][]string
	header := false
	for i, line := range strings.Split(string(b), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if !header {
			header = true
			if !reflect.DeepEqual(f, want) {
				return nil, fmt.Errorf("%s: header is %v, want %v", path, f, want)
			}
			continue
		}
		if len(f) != len(want) {
			return nil, fmt.Errorf("%s line %d: %d field(s), want %d: %q", path, i+1, len(f), len(want), line)
		}
		out = append(out, f)
	}
	return out, nil
}

func loadDetectorCensus(t *testing.T) []detectorCensusRow {
	t.Helper()
	recs, err := readCensusTSV(detectorCensusPath, detectorCensusColumns)
	if err != nil {
		t.Fatalf("%v", err)
	}
	var out []detectorCensusRow
	for _, f := range recs {
		out = append(out, detectorCensusRowFrom(f))
	}
	// Anti-vacuity. Every assertion below is a loop over this slice, so an
	// emptied census would pass every one of them having compared nothing.
	// The floor is the seeded population's order of magnitude, not a number
	// somebody picked: migrations/core seeds three digits of detection rows
	// and a census holding fewer than fifty has lost most of them.
	if len(out) < 50 {
		t.Fatalf("the census holds %d row(s); a census this small cannot describe the seeded detection set, "+
			"and every check in this file loops over it", len(out))
	}
	seen := map[string]bool{}
	for _, r := range out {
		if seen[r.PolicyID] {
			t.Errorf("duplicate policy_id %q: the census is keyed by policy_id and a duplicate makes "+
				"the set comparison below ambiguous", r.PolicyID)
		}
		seen[r.PolicyID] = true
	}
	return out
}

// censusResolveValidator reproduces PolicyLoader.getValidatorForPolicy exactly:
// policy-id token first, category default second. It is the ONE definition of
// "is this row algorithmic", and it is the loader's own, not a copy of the
// rules.
func censusResolveValidator(policyID, category string) ValidatorFunc {
	if v := ValidatorForPolicyID(policyID); v != nil {
		return v
	}
	return GetValidatorForCategory(PolicyCategory(category))
}

// censusPostureLever answers "which detection-posture lever displaces this
// row's action" by calling the function the rest of the platform calls, not by
// looking the category up in legacy_posture_levers.tsv.
//
// This matters for the same reason the class is derived rather than read: the
// two are NOT equivalent for a category nobody has seeded yet.
// PostureLeverForCategory routes PII through IsPIIPolicyCategory, which is
// PREFIX-derived (`pii-*`) precisely so a newly seeded jurisdiction is included
// with no list to forget (#2965); legacy_posture_levers.tsv is an enumerated
// list. A future `pii-brazil` row would take PII_ACTION from the code and `-`
// from the table, and a census keyed off the table would pin the wrong answer
// while staying green.
//
// types.go says of PostureLeverForCategory that it is "the SHARED source for
// that question, deliberately not a third copy". This census is its fourth
// reader and calls it like the other three.
func censusPostureLever(category string) string {
	if lever := PostureLeverForCategory(PolicyCategory(category)); lever != "" {
		return lever
	}
	return "-"
}

// validatorBearingEvaluators are the legacy entry points that run the SHARED
// pattern engine, and therefore the ones on which a class (b) row's validator
// actually gates the match.
//
// THIS IS THE QUALIFICATION THE FIRST VERSION OF THIS CENSUS WAS MISSING, and
// it is load bearing: the class is a property of an evaluator, not of the
// platform. `EvaluateRequest` and `EvaluateResponse` are
// UnifiedPolicyEngine's (platform/shared/policy/engine.go), which build a
// PatternEvaluator with the loader-resolved validator attached.
// `EvaluatePolicy` is TierAwarePolicyEngine's
// (platform/agent/tier_aware_policy_engine.go), whose evaluateFirstMatch does
// `re.MatchString(input)` and returns - that file contains no Validator
// reference at all. `EvaluateDynamicPolicies` reads dynamic_policies and never
// sees a static row.
//
// So on the proxy_tier plane every "algorithmic" row runs as a bare regex: the
// Luhn check does not gate sys_pii_credit_card there, and sys_pii_booking_ref
// - validator-inert on the fully-gated planes because its category default
// rejects every non-card string - is NOT inert there and fires on any token
// its pattern matches.
//
// proxy_tier is the only plane where NO static site runs a validator. It is
// not the only plane where a bare pattern decides: policy_test runs both kinds
// of site under one plane name and is rendered "(mixed)" - see
// mixedPlaneSuffix.
var validatorBearingEvaluators = map[string]bool{
	"EvaluateRequest":  true,
	"EvaluateResponse": true,
}

// staticEvaluators are the legacy entry points that read static_policies at
// all. EvaluateDynamicPolicies reads dynamic_policies and never sees a static
// row, so a plane whose only site is that one is not part of this question.
var staticEvaluators = map[string]bool{
	"EvaluateRequest":  true,
	"EvaluateResponse": true,
	"EvaluatePolicy":   true,
}

// mixedPlaneSuffix marks a plane that runs BOTH kinds of static site.
//
// The first version of this derivation was binary - a plane counted as
// validator-bearing if ANY of its sites was - and that is wrong for exactly
// one plane, because the legacy plane taxonomy is not consistent about
// splitting a handler's phases. clientRequestHandler's two phases were given
// two plane NAMES (proxy_request for its EvaluateRequest site, proxy_tier for
// its EvaluatePolicy one), so each name is unambiguous. policyTestHandler has
// the same two-phase shape and only ONE name, so `policy_test` carries an
// EvaluateRequest site and an EvaluatePolicy site at once: a validator gates
// one phase there and the bare pattern decides the other. Labelling it
// validator-bearing claims a gate that half of it does not have.
const mixedPlaneSuffix = "(mixed)"

// planeValidatorKind is the three-valued answer for one static plane.
type planeValidatorKind int

const (
	planeBare      planeValidatorKind = iota // no static site runs a validator
	planeValidator                           // every static site runs a validator
	planeMixed                               // both kinds of static site
)

// loadValidatorBearingPlanes reads legacy_call_sites.tsv and classifies every
// plane with a static call site as bare, validator-gated or mixed.
func loadValidatorBearingPlanes(t *testing.T) map[string]planeValidatorKind {
	t.Helper()
	b, err := os.ReadFile(callSitesPath)
	if err != nil {
		t.Fatalf("reading %s: %v", callSitesPath, err)
	}
	hasValidator := map[string]bool{}
	hasBare := map[string]bool{}
	seenEvaluator := map[string]bool{}
	for i, line := range strings.Split(string(b), "\n") {
		if i == 0 || line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			t.Fatalf("%s line %d: %d field(s), want at least 2", callSitesPath, i+1, len(f))
		}
		seenEvaluator[f[1]] = true
		if !staticEvaluators[f[1]] {
			continue
		}
		if validatorBearingEvaluators[f[1]] {
			hasValidator[f[0]] = true
		} else {
			hasBare[f[0]] = true
		}
	}
	// Anti-vacuity in the direction that matters: if the call-sites table ever
	// renames its evaluators, every plane silently becomes bare and every (b)
	// row's qualification would widen to "nowhere" while passing.
	for name := range staticEvaluators {
		if !seenEvaluator[name] {
			t.Fatalf("%s names no %q call site; the validator classification would be vacuous",
				callSitesPath, name)
		}
	}
	out := map[string]planeValidatorKind{}
	for p := range hasValidator {
		if hasBare[p] {
			out[p] = planeMixed
		} else {
			out[p] = planeValidator
		}
	}
	for p := range hasBare {
		if !hasValidator[p] {
			out[p] = planeBare
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s yields no static plane at all", callSitesPath)
	}
	return out
}

// censusValidatorPlanes renders the planes on which a validator gates the
// match, marking a plane that gates on only some of its phases.
func censusValidatorPlanes(planes string, kind map[string]planeValidatorKind) string {
	if planes == "-" || planes == "" {
		return "-"
	}
	var keep []string
	for _, p := range strings.Split(planes, ",") {
		switch kind[p] {
		case planeValidator:
			keep = append(keep, p)
		case planeMixed:
			keep = append(keep, p+mixedPlaneSuffix)
		}
	}
	return censusJoinOrDash(keep)
}

// censusNonValidatorPlanes lists the planes a row evaluates on where the bare
// pattern decides - wholly (bare) or on one of its phases (mixed).
func censusNonValidatorPlanes(planes string, kind map[string]planeValidatorKind) string {
	if planes == "-" || planes == "" {
		return "-"
	}
	var keep []string
	for _, p := range strings.Split(planes, ",") {
		switch kind[p] {
		case planeBare:
			keep = append(keep, p)
		case planeMixed:
			keep = append(keep, p+mixedPlaneSuffix)
		}
	}
	return censusJoinOrDash(keep)
}

// censusValidatorSite renders the defining file and symbol of a validator function.
// Derived through runtime.FuncForPC so the census cannot cite a function that
// does not exist or has moved.
func censusValidatorSite(v ValidatorFunc) (string, error) {
	if v == nil {
		return "", fmt.Errorf("nil validator")
	}
	pc := reflect.ValueOf(v).Pointer()
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "", fmt.Errorf("no function for pc")
	}
	file, _ := fn.FileLine(pc)
	name := fn.Name()
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	// Render repository-relative so the census does not embed a build path.
	// LastIndex, not Index. A checkout path can itself contain "/platform/" -
	// a GitHub-hosted runner's default is /home/runner/work/<repo>/<repo>, and
	// a repository or working directory named "platform" anywhere above the
	// tree makes the FIRST occurrence the wrong one. The repo-relative suffix
	// is always the LAST /platform/-rooted segment, and getting it wrong
	// reports as a census defect rather than as the path-rendering defect it
	// is, which is the confusing direction.
	idx := strings.LastIndex(file, "/platform/")
	if idx < 0 {
		return "", fmt.Errorf("validator file %q is outside the repository", file)
	}
	return strings.TrimPrefix(file[idx:], "/") + "::" + name, nil
}

// TestDetectorCensusClassIsTheCodeThatRuns is the half that needs no database.
//
// It recomputes every row's class from the loader's own validator resolution
// and every algorithmic row's implementation site from the running binary. A
// row classified by its name, or citing a function the evaluator does not
// call, is red here on every CI tier.
func TestDetectorCensusClassIsTheCodeThatRuns(t *testing.T) {
	rows := loadDetectorCensus(t)

	bearing := loadValidatorBearingPlanes(t)
	algorithmicWithBarePlane := 0

	counts := map[string]int{classPattern: 0, classAlgorithmic: 0, classNotADetector: 0}
	for _, r := range rows {
		if _, ok := counts[r.Class]; !ok {
			t.Errorf("%s: class %q is not one of pattern|algorithmic|not_a_detector", r.PolicyID, r.Class)
			continue
		}
		counts[r.Class]++

		v := censusResolveValidator(r.PolicyID, r.Category)
		switch r.Class {
		case classAlgorithmic:
			if v == nil {
				t.Errorf("%s: censused algorithmic, but getValidatorForPolicy(%q, %q) resolves NO validator, "+
					"so the evaluator runs the pattern alone. Classified by name, not by code.",
					r.PolicyID, r.PolicyID, r.Category)
				continue
			}
			site, err := censusValidatorSite(v)
			if err != nil {
				t.Errorf("%s: cannot resolve the implementation site: %v", r.PolicyID, err)
				continue
			}
			if r.ImplSite != site {
				t.Errorf("%s: census cites impl_site %q, the evaluator calls %q",
					r.PolicyID, r.ImplSite, site)
			}
		case classPattern:
			if v != nil {
				site, _ := censusValidatorSite(v)
				t.Errorf("%s: censused pattern, but the evaluator resolves the validator %s for it, "+
					"so a match is gated by an algorithm the census does not record", r.PolicyID, site)
			}
			// Anchored, not HasPrefix. A prefix check accepts a bare
			// "re2:sha256:" with no digest at all, and the digest is only
			// compared against the real pattern in the database half - which
			// does not run on a pull_request. The error message promised a
			// shape the check did not enforce.
			if !patternImplSiteRe.MatchString(r.ImplSite) {
				t.Errorf("%s: a pattern row's impl_site must be the pattern's dialect and digest "+
					"matching %s, got %q", r.PolicyID, patternImplSiteRe, r.ImplSite)
			}
		case classNotADetector:
			if r.ImplSite != "-" {
				t.Errorf("%s: a not_a_detector row inspects no content and has no implementation site, got %q",
					r.PolicyID, r.ImplSite)
			}
		}

		// validator_planes is held to the same standard as the class, and on
		// the tier with no database, because it is the qualification that
		// makes the class claim true. Derived by intersecting the row's planes
		// with the validator-bearing set from legacy_call_sites.tsv.
		if want := censusValidatorPlanes(r.Planes, bearing); r.ValidatorPlanes != want {
			t.Errorf("%s: census records validator_planes %q; intersecting planes %q with the "+
				"validator-bearing planes from %s gives %q",
				r.PolicyID, r.ValidatorPlanes, r.Planes, callSitesPath, want)
		}
		if r.Class == classAlgorithmic {
			nonValidator := censusNonValidatorPlanes(r.Planes, bearing)
			if nonValidator != "-" {
				algorithmicWithBarePlane++
			}
		}

		// The posture lever is held to the SAME standard as the class: it is
		// the answer PostureLeverForCategory gives, not a name looked up in a
		// table. Checked here so it is held on every tier, including the one
		// with no database.
		if want := censusPostureLever(r.Category); r.PostureLever != want {
			t.Errorf("%s: census records posture_lever %q, PostureLeverForCategory(%q) answers %q",
				r.PolicyID, r.PostureLever, r.Category, want)
		}

		// The emit column is a SET; every member must be in the vocabulary,
		// and a "Permission" member is a compiler defect rather than a value.
		for _, e := range strings.Split(r.Emit, "|") {
			if e != emitDeny && e != emitEscalate && e != emitSignal && e != emitNone {
				t.Errorf("%s: adr065_emit member %q is not one of Deny, Escalate, Signal or -", r.PolicyID, e)
			}
		}
		if r.Emit != emitNone && strings.Contains(r.Emit, emitNone) {
			t.Errorf("%s: adr065_emit %q mixes %q with a real emit; %q means the row emits nothing anywhere",
				r.PolicyID, r.Emit, emitNone, emitNone)
		}
	}

	// A row whose category is outside this package's own enum resolves NO
	// category-default validator and NO detection-posture lever, because both
	// tables are pinned against AllPolicyCategories. That is a real per-row
	// fact and it must be RECORDED rather than left to be rediscovered, so
	// such a row is required to carry an exceptions note.
	declared := map[string]bool{}
	for _, c := range AllPolicyCategories() {
		declared[string(c)] = true
	}
	unregistered := map[string]int{}
	for _, r := range rows {
		if declared[r.Category] {
			continue
		}
		unregistered[r.Category]++
		if r.Exceptions == "-" || strings.TrimSpace(r.Exceptions) == "" {
			t.Errorf("%s: category %q is not in AllPolicyCategories, so this row resolves no category "+
				"default and no posture lever, and the census records no exception for it",
				r.PolicyID, r.Category)
		}
	}
	var ucats []string
	for c := range unregistered {
		ucats = append(ucats, c)
	}
	sort.Strings(ucats)
	for _, c := range ucats {
		t.Logf("unregistered category %-18s %3d row(s)", c, unregistered[c])
	}
	t.Logf("unregistered categories: %d covering %d row(s)", len(unregistered), func() int {
		n := 0
		for _, v := range unregistered {
			n += v
		}
		return n
	}())

	// Print the census INCLUDING the zero buckets: a class that has emptied
	// out is exactly the change nobody notices in a count of the others.
	for _, c := range []string{classPattern, classAlgorithmic, classNotADetector} {
		t.Logf("class %-14s %3d row(s)", c, counts[c])
	}
	t.Logf("total %d row(s)", len(rows))
	// Printed including zero. This is the population for which the class is
	// TRUE ONLY ON SOME PLANES: on the rest their validator never runs and the
	// pattern alone decides. A zero here would mean the qualification had
	// silently stopped being derived, not that the problem had gone away.
	t.Logf("algorithmic rows with at least one NON-validator-bearing plane: %d of %d",
		algorithmicWithBarePlane, counts[classAlgorithmic])
	if counts[classAlgorithmic] > 0 && algorithmicWithBarePlane == 0 {
		t.Error("every algorithmic row is validator-gated on every plane it evaluates on; that would be " +
			"a change in the platform, so either legacy_call_sites.tsv or the planes column has stopped " +
			"being derived")
	}

	// Both real classes must be populated. The whole point of the census is
	// that the boundary has two sides; a census that found only one side has
	// either lost the derivation or lost the data.
	if counts[classAlgorithmic] == 0 {
		t.Error("no algorithmic rows: the (a)/(b) boundary this census exists to draw is not being derived")
	}
	if counts[classPattern] == 0 {
		t.Error("no pattern rows: the (a)/(b) boundary this census exists to draw is not being derived")
	}
}

// TestCensusMatchesTheForwardSeededMigrations is the set comparison WITHOUT a
// database, and it is what closes the gap the first version of this PR
// disclosed as structural.
//
// It is not structural. Two facts already established here make the live set
// derivable from the tree alone: censusSeedProvenance parses every forward
// INSERT into static_policies (and refuses a statement that does not name
// policy_id first), and no forward migration has ever DELETED a static_policies
// row - `DELETE FROM static_policies` appears only in *_down.sql files, which
// is finding 5 of this census. Forward-seeded therefore IS live, and the
// equality can be asserted on every CI tier rather than only where a migrated
// database exists.
//
// That matters because the database half runs in neither the pull_request
// board nor, under admin merges, the merge queue. Without this test, deleting
// a census row and adjusting the fold table's count to match was green on the
// only tier this PR's board runs.
func TestCensusMatchesTheForwardSeededMigrations(t *testing.T) {
	census := loadDetectorCensus(t)
	_, seededIDs := censusSeedProvenance(t)

	if len(seededIDs) == 0 {
		t.Fatal("no forward migration seeds a static_policies row; the comparison below would be vacuous")
	}

	inCensus := map[string]bool{}
	for _, c := range census {
		inCensus[c.PolicyID] = true
	}

	var missingFromCensus, missingFromMigrations []string
	for id := range seededIDs {
		if !inCensus[id] {
			missingFromCensus = append(missingFromCensus, id)
		}
	}
	for id := range inCensus {
		if _, ok := seededIDs[id]; !ok {
			missingFromMigrations = append(missingFromMigrations, id)
		}
	}
	sort.Strings(missingFromCensus)
	sort.Strings(missingFromMigrations)

	if len(missingFromCensus) > 0 {
		t.Errorf("%d row(s) seeded by a forward migration are NOT in the census: %v\n"+
			"A seeded detection row with no class is a v11 scope item nobody counted.",
			len(missingFromCensus), missingFromCensus)
	}
	if len(missingFromMigrations) > 0 {
		t.Errorf("%d census row(s) are seeded by no forward migration: %v\n"+
			"Either the census describes a row no deployment has, or a seed moved somewhere this "+
			"parse does not read.", len(missingFromMigrations), missingFromMigrations)
	}
	t.Logf("forward-seeded static rows: %d; census rows: %d; seeded-not-censused: %d; censused-not-seeded: %d",
		len(seededIDs), len(census), len(missingFromCensus), len(missingFromMigrations))
}

// TestEveryPostureLeverHasADestination holds detection_posture_fold.tsv to the
// levers that actually exist, in both directions, and recomputes each lever's
// affected population from the census.
//
// A lever with no destination is the failure mode this checks for: the
// operator asked for Detection Posture to be folded into scoring thresholds
// and tool posture, and a lever nobody assigned a home to is a deployment
// setting that silently stops working at v11.
//
// It reads the TSV and NOT technical-docs/designs/DETECTOR_REGISTRY_DESIGN.md,
// for two reasons. The design doc does not reach the community mirror - checked
// with scripts/ci/simulate-community-mirror.sh, which stages this package and
// this fixture and does not stage technical-docs - so a test parsing it would
// go red on the mirror over a file that is correctly absent there. And parsing
// a markdown table with a regular expression to assert a fact is a fragile way
// to hold prose to data when the data can simply be the artifact.
func TestEveryPostureLeverHasADestination(t *testing.T) {
	b, err := os.ReadFile(postureLeversPath)
	if err != nil {
		t.Fatalf("reading %s: %v", postureLeversPath, err)
	}
	levers := map[string]bool{}
	for i, line := range strings.Split(string(b), "\n") {
		if i == 0 || line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 2 {
			t.Fatalf("%s line %d: %d field(s), want 2", postureLeversPath, i+1, len(f))
		}
		if f[1] != "-" {
			levers[f[1]] = true
		}
	}
	if len(levers) == 0 {
		t.Fatalf("%s names no posture lever at all; the fold table would be vacuously complete", postureLeversPath)
	}

	recs, err := readCensusTSV(postureFoldPath, postureFoldColumns)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// The affected population is recomputed from the census, so a lever whose
	// rows move without this file moving is red.
	wantRows := map[string]int{}
	for _, c := range loadDetectorCensus(t) {
		if c.PostureLever != "-" {
			wantRows[c.PostureLever]++
		}
	}

	found := map[string]string{}
	for _, f := range recs {
		lever, dest, rows := f[0], f[1], f[2]
		if !levers[lever] {
			t.Errorf("the fold table names lever %q, which %s does not list; a destination for a lever "+
				"that does not exist folds nothing", lever, postureLeversPath)
			continue
		}
		if strings.TrimSpace(dest) == "" || dest == "-" {
			t.Errorf("lever %s has no destination; it is a deployment setting that would silently stop "+
				"working at v11", lever)
			continue
		}
		found[lever] = dest
		n, convErr := strconv.Atoi(rows)
		if convErr != nil {
			t.Errorf("lever %s: census_rows %q is not a number", lever, rows)
			continue
		}
		if n != wantRows[lever] {
			t.Errorf("lever %s: the fold table claims %d census row(s), the census holds %d",
				lever, n, wantRows[lever])
		}
	}

	var missing []string
	for lever := range levers {
		if found[lever] == "" {
			missing = append(missing, lever)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("posture lever(s) with no row in %s: %v", postureFoldPath, missing)
	}

	var names []string
	for lever := range levers {
		names = append(names, lever)
	}
	sort.Strings(names)
	for _, n := range names {
		t.Logf("posture lever %-24s %3d row(s) -> %s", n, wantRows[n], found[n])
	}
	t.Logf("%d lever(s), %d without a destination", len(levers), len(missing))
}

// ---------------------------------------------------------------------------
// The database half.
// ---------------------------------------------------------------------------

// capturedOnce memoises the produced capture for the whole test binary.
//
// Two tests need a capture and the data is byte-identical, so producing it
// twice means two postgres containers and two runs of all 155 core migrations
// for one answer. The lane this lands in is docker-daemon-bound by its own
// account - test.yml bounds it at `-p 4` because "~9 of the platform packages
// each spin their own throwaway postgres container; left unbounded on a
// high-core runner they overwhelm the docker daemon and intermittently red" -
// and this package should be a tenth at one container, not at two.
var capturedOnce struct {
	sync.Once
	dir     string
	tmpRoot string
	log     string
	err     error
}

// TestMain removes the memoised capture directory after the last test.
//
// The capture cannot live in a t.TempDir because it is shared by two tests, so
// its cleanup has to outlive both. Without this, every `go test` on a machine
// that runs the database halves leaves a $TMPDIR/detector-census-capture-*
// behind - measured at one per run - which on a CI host with a persistent /tmp
// accumulates silently until somebody is debugging a full disk.
func TestMain(m *testing.M) {
	code := m.Run()
	if capturedOnce.tmpRoot != "" {
		_ = os.RemoveAll(capturedOnce.tmpRoot)
	}
	os.Exit(code)
}

// isCommunityMirrorTree reports whether the tree under root is the published
// community mirror rather than the enterprise repository.
//
// The signal is the community sync's OWN observable outcome, not a guess:
// .github/workflows/lint.yml is synced to the mirror and
// .github/workflows/sync-community-repo.yml is excluded from it, so the pair
// "lint present, sync absent" is true on the mirror and false here. This is the
// same derivation #3807 established for a guard that has to behave differently
// on the two trees.
func isCommunityMirrorTree(root string) bool {
	if _, err := os.Stat(filepath.Join(root, ".github", "workflows", "lint.yml")); err != nil {
		return false
	}
	_, err := os.Stat(filepath.Join(root, ".github", "workflows", "sync-community-repo.yml"))
	return os.IsNotExist(err)
}

// detectorCaptureDir resolves a capture of a migrated database.
//
// It prefers an AXONFLOW_LEGACY_CAPTURE_DIR the caller supplied, and otherwise
// PRODUCES one under TEST_PG_INTEGRATION=1 by running the capture script into a
// temporary directory. Producing it is the difference between a ratchet and a
// report: no CI job sets AXONFLOW_LEGACY_CAPTURE_DIR, so a test that only
// consumed one would have skipped on every tier for ever while printing a
// reassuring reason. TEST_PG_INTEGRATION=1 is the repository's existing gate
// for a test that stands up its own postgres (system_policy_count_realpg_test.go
// does the same thing through os/exec), and the enterprise-tagged Real-PG lane
// in test.yml sets it for `go test ./...` across platform/.
//
// ON THE COMMUNITY MIRROR THE SCRIPT IS NOT THERE, AND THAT IS CORRECT.
// scripts/legacy-policy-capture.sh does not survive the community sync while
// this test and its fixtures do, so a hard failure on the missing script would
// be exactly the mirror-side red this file avoids elsewhere by keeping the fold
// table in a fixture rather than in a document. On the mirror the two database
// halves skip and say why; on the enterprise tree a missing script is still
// fatal, because there it means the script was deleted.
func detectorCaptureDir(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("AXONFLOW_LEGACY_CAPTURE_DIR"); dir != "" {
		return dir
	}
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("no AXONFLOW_LEGACY_CAPTURE_DIR and TEST_PG_INTEGRATION is not 1: the census was NOT " +
			"compared against a migrated database, so neither direction of the set comparison ran. " +
			"Produce a capture with scripts/legacy-policy-capture.sh and set the variable, or set " +
			"TEST_PG_INTEGRATION=1 and let this test produce one.")
	}

	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	script := filepath.Join(root, "scripts", "legacy-policy-capture.sh")
	if _, statErr := os.Stat(script); statErr != nil {
		if isCommunityMirrorTree(root) {
			t.Skipf("scripts/legacy-policy-capture.sh is not part of the community mirror, so no capture "+
				"can be produced on this tree and the set comparison did NOT run. The census fixtures and "+
				"the checks that need no database DID run. (%v)", statErr)
		}
		t.Fatalf("%s is not present on an enterprise tree, so no capture can be produced: %v", script, statErr)
	}

	capturedOnce.Do(func() {
		dir, mkErr := os.MkdirTemp("", "detector-census-capture-")
		if mkErr != nil {
			capturedOnce.err = mkErr
			return
		}
		// The directory outlives the test that created it - both tests read
		// it - so it cannot be a t.TempDir. TestMain removes it after the last
		// test, because a capture directory left behind on a CI host is the
		// kind of litter that is invisible until the disk is full.
		capturedOnce.tmpRoot = dir
		out := filepath.Join(dir, "capture")
		// A deadline: a hung `docker run` on a cold runner would otherwise
		// block until the package's own -timeout, which reports as the whole
		// package timing out rather than as this step hanging.
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "bash", script, out)
		cmd.Dir = root
		// SIGTERM on cancellation, NOT the default SIGKILL. The capture script
		// traps INT and TERM specifically so it can `docker rm -fv` its own
		// container, and SIGKILL is untrappable - so the default would leak a
		// postgres container on exactly the timeout path this deadline exists
		// to handle. WaitDelay then bounds how long the handler gets before
		// the process is killed anyway.
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = 30 * time.Second
		// An EPHEMERAL host port, not a derived one. A port computed from the
		// pid narrows the collision window but does not close it: the lane
		// runs several test binaries at once and two pids congruent modulo any
		// fixed span pick the same port, which surfaces as a migration
		// failure rather than as a port clash. Port 0 lets the kernel choose,
		// and the script reaches postgres through `docker exec` rather than
		// the published port, so nothing depends on knowing which one it got.
		cmd.Env = append(os.Environ(), "AXONFLOW_PG_PORT=0")
		combined, runErr := cmd.CombinedOutput()
		capturedOnce.log = string(combined)
		if runErr != nil {
			capturedOnce.err = runErr
			return
		}
		capturedOnce.dir = out
	})
	if capturedOnce.err != nil {
		t.Fatalf("producing a capture with %s failed: %v\n%s", script, capturedOnce.err, capturedOnce.log)
	}
	t.Logf("capture (produced once for this test binary):\n%s", capturedOnce.log)
	return capturedOnce.dir
}

// toleratedMigrationFailures is the reviewed set of migrations that do not
// apply cleanly in the capture's bare-postgres environment and that the capture
// script correctly tolerates because they do not touch the policy tables.
//
// 028 needs a grafana role the capture does not create. The script PRINTS every
// failure and hard-fails on one that greps `static_policies|dynamic_policies`,
// so nothing is swallowed - but "printed" is not "checked", and a second
// non-policy migration starting to fail on CI would pass here while the log
// named it. Pinning the set makes that a red.
var toleratedMigrationFailures = map[string]bool{
	"028_grafana_database.sql": true,
}

// assertToleratedMigrationFailures reads the capture's own migration-errors.log
// and refuses a failure outside the reviewed set.
func assertToleratedMigrationFailures(t *testing.T, dir string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "migration-errors.log"))
	if err != nil {
		// A capture supplied by hand may predate this file. Say so rather than
		// treating its absence as a clean result.
		t.Logf("no migration-errors.log in the capture, so the tolerated-failure set was NOT checked: %v", err)
		return
	}
	// The log is `=== <file> ===` headers followed by that file's stderr. A
	// file whose section carries any content failed.
	var current string
	unexpected := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "=== ") && strings.HasSuffix(line, " ===") {
			current = strings.TrimSuffix(strings.TrimPrefix(line, "=== "), " ===")
			continue
		}
		// Only an ERROR marks a failure. psql emits NOTICE lines from
		// successful migrations too (IF EXISTS drops, DO blocks), and an
		// earlier version of this check treated any content as a failure and
		// reported 112 of 155 migrations as broken while every one had
		// applied. The script's own fatal test greps this same log.
		if current == "" || !strings.Contains(line, "ERROR:") {
			continue
		}
		if !toleratedMigrationFailures[current] {
			unexpected[current] = true
		}
	}
	var names []string
	for n := range unexpected {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > 0 {
		t.Errorf("migration(s) outside the reviewed tolerated set did not apply cleanly: %v\n"+
			"The capture tolerates a failure that does not touch the policy tables, but the set is "+
			"reviewed. Either the environment regressed or the set needs a new entry with a reason.", names)
	}
	t.Logf("tolerated migration failures: %d reviewed, %d unexpected", len(toleratedMigrationFailures), len(names))
}

func loadDetectorCaptureRows(t *testing.T, dir string) []legacycompile.RawRow {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "capture-owner.json"))
	if err != nil {
		t.Fatalf("reading the capture: %v", err)
	}
	var rows []legacycompile.RawRow
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatalf("decoding the capture: %v", err)
	}
	return rows
}

// column reads a captured column as a string, reporting SQL NULL as "".
func captureColumn(r legacycompile.RawRow, name string) string {
	raw, ok := r.Columns[name]
	if !ok || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return strconv.FormatBool(b)
	}
	return strings.Trim(string(raw), `"`)
}

// detectorEmitFor projects the compiled policies' Authority into the
// operator's emit vocabulary. It is a PROJECTION of what legacycompile already
// decided, never a second mapping from the legacy action: two mappings would
// drift and the census would then describe an import nobody performs.
//
// The result is a SET, rendered "Deny|Signal" when a row emits differently on
// different planes. Forty of the hundred-and-one rows carry
// read_path_action_divergence - the legacy row's two read paths resolve to
// different actions, so what the row does depends on which plane asked - and
// on TWELVE of those forty the divergence reaches the emit. Collapsing those
// twelve to the strongest value would have hidden the corpus's largest defect
// class behind a column that looked decided; the other twenty-eight diverge in
// a way the emit projection does not distinguish, and the reason code is what
// carries them.
func detectorEmitFor(rec legacycompile.Record) (string, []string) {
	emits := map[string]bool{}
	obs := map[string]bool{}
	for _, p := range rec.Planes {
		for _, pol := range p.Policies {
			for _, o := range pol.Obligations {
				obs[string(o.Type)] = true
			}
			switch pol.Authority {
			case contract.AuthorityConstraint:
				emits[emitDeny] = true
			case contract.AuthorityRequirement:
				escalate := false
				for _, o := range pol.Obligations {
					if o.Type == contract.ObApprovalChallenge {
						escalate = true
					}
				}
				if escalate {
					emits[emitEscalate] = true
				} else {
					emits[emitSignal] = true
				}
			case contract.AuthorityInspection:
				emits[emitSignal] = true
			case contract.AuthorityPermission:
				// A detector cannot grant. If one ever compiles to a
				// permission that is a compiler defect, and saying so here is
				// cheaper than discovering it in the portal.
				emits["Permission(INVALID)"] = true
			}
		}
	}
	// Stable, meaningful order: strongest first, so "Deny|Signal" reads the
	// same way every time and a map's iteration order cannot reorder it.
	var emit []string
	for _, e := range []string{emitDeny, emitEscalate, emitSignal, "Permission(INVALID)"} {
		if emits[e] {
			emit = append(emit, e)
		}
	}
	out := emitNone
	if len(emit) > 0 {
		out = strings.Join(emit, "|")
	}
	var list []string
	for o := range obs {
		list = append(list, o)
	}
	sort.Strings(list)
	return out, list
}

func detectorDispositionOf(rec legacycompile.Record) (string, []string) {
	codes := map[string]bool{}
	for _, r := range rec.Reasons {
		codes[string(r.Code)] = true
	}
	for _, p := range rec.Planes {
		for _, r := range p.Reasons {
			codes[string(r.Code)] = true
		}
	}
	var list []string
	for c := range codes {
		list = append(list, c)
	}
	sort.Strings(list)
	return string(rec.Status), list
}

func detectorPlanesOf(rec legacycompile.Record) []string {
	seen := map[string]bool{}
	for _, p := range rec.Planes {
		if len(p.Policies) > 0 {
			seen[string(p.Plane)] = true
		}
	}
	var list []string
	for p := range seen {
		list = append(list, p)
	}
	sort.Strings(list)
	return list
}

func censusPatternDigest(pattern string) string {
	sum := sha256.Sum256([]byte(pattern))
	return "re2:sha256:" + hex.EncodeToString(sum[:])[:12]
}

// derivedRow builds the census row for one captured static row from the
// capture, the loader's validator resolution and the compiler's record.
// Everything except `exceptions` is machine-derived; `exceptions` is the one
// reviewed column and is carried over from the committed census.
func derivedCensusRow(raw legacycompile.RawRow, rec legacycompile.Record, seededBy map[string]string, bearing map[string]planeValidatorKind) detectorCensusRow {
	policyID := captureColumn(raw, "policy_id")
	category := captureColumn(raw, "category")
	pattern := captureColumn(raw, "pattern")

	class := classPattern
	implSite := censusPatternDigest(pattern)
	if pattern == "" {
		class = classNotADetector
		implSite = "-"
	}
	if v := censusResolveValidator(policyID, category); v != nil && pattern != "" {
		class = classAlgorithmic
		if site, err := censusValidatorSite(v); err == nil {
			implSite = site
		} else {
			implSite = "UNRESOLVED:" + err.Error()
		}
	}

	emit, obs := detectorEmitFor(rec)
	status, reasons := detectorDispositionOf(rec)
	planes := detectorPlanesOf(rec)

	lever := censusPostureLever(category)
	seed := seededBy[policyID]
	if seed == "" {
		seed = "-"
	}
	return detectorCensusRow{
		PolicyID:           policyID,
		Name:               captureColumn(raw, "name"),
		Category:           category,
		Tier:               captureColumn(raw, "tier"),
		Enabled:            captureColumn(raw, "enabled"),
		Class:              class,
		ImplSite:           implSite,
		LegacyAction:       captureColumn(raw, "action"),
		Severity:           captureColumn(raw, "severity"),
		Emit:               emit,
		Obligations:        censusJoinOrDash(obs),
		PostureLever:       lever,
		Disposition:        status,
		DispositionReasons: censusJoinOrDash(reasons),
		Planes:             censusJoinOrDash(planes),
		ValidatorPlanes:    censusValidatorPlanes(censusJoinOrDash(planes), bearing),
		SeedMigration:      seed,
	}
}

func censusJoinOrDash(in []string) string {
	if len(in) == 0 {
		return "-"
	}
	return strings.Join(in, ",")
}

// insertHeaderRe finds an `INSERT INTO static_policies (cols...) VALUES`
// header. Only static_policies: dynamic_policies has its own family and
// mixing the two produced a "superseded" list full of live dynamic rows the
// first time this was written.
var insertHeaderRe = regexp.MustCompile(`(?is)INSERT\s+INTO\s+(?:public\.)?static_policies\s*\(([^)]*)\)\s*VALUES`)

// censusSeedProvenance maps a policy_id to the migration file(s) that INSERT
// it into static_policies, in filename order.
//
// It PARSES the INSERT rather than grepping for quoted literals. A grep is
// what the first version did, and it reported `pii_detection` (a category
// value), `sql_injection` (likewise) and ten `sys_dyn_*` ids (rows that are
// live in dynamic_policies) as seeded static policies - three whole classes of
// false positive, every one of which would have become a census row asserting
// something untrue. The parse takes the FIRST column of each VALUES tuple and
// refuses a statement whose first column is not policy_id, so a future
// migration that reorders the column list fails loudly instead of censusing
// the wrong field.
func censusSeedProvenance(t *testing.T) (byPolicy map[string]string, seededIDs map[string][]string) {
	t.Helper()
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(root, "migrations", "core", "*.sql"))
	if err != nil {
		t.Fatalf("globbing migrations: %v", err)
	}
	sort.Strings(files)
	byPolicy = map[string]string{}
	seededIDs = map[string][]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_down.sql") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		base := filepath.Base(f)
		for _, loc := range insertHeaderRe.FindAllStringSubmatchIndex(string(src), -1) {
			cols := strings.Split(string(src)[loc[2]:loc[3]], ",")
			if len(cols) == 0 || strings.TrimSpace(cols[0]) != "policy_id" {
				t.Fatalf("%s: an INSERT INTO static_policies does not name policy_id first (%q); "+
					"the provenance scan would attribute the wrong column", base, strings.TrimSpace(cols[0]))
			}
			for _, id := range firstLiteralPerTuple(string(src)[loc[1]:]) {
				if len(seededIDs[id]) == 0 || seededIDs[id][len(seededIDs[id])-1] != base {
					seededIDs[id] = append(seededIDs[id], base)
				}
			}
		}
	}
	for id, fs := range seededIDs {
		byPolicy[id] = fs[0]
	}
	return byPolicy, seededIDs
}

// firstLiteralPerTuple scans the VALUES list that follows an INSERT header and
// returns the first single-quoted literal of each top-level tuple, stopping at
// the statement's terminating semicolon.
//
// It tracks quote state (with the SQL ” escape), line and block comments, and
// parenthesis depth, so a regex inside a pattern literal - and these rows are
// nothing but regexes, full of parentheses and quotes - cannot desynchronise
// the scan.
func firstLiteralPerTuple(s string) []string {
	var out []string
	depth := 0
	inQuote := false
	tupleStarted := false
	haveFirst := false
	var lit strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					lit.WriteByte('\'')
					i++
					continue
				}
				inQuote = false
				if tupleStarted && !haveFirst {
					out = append(out, lit.String())
					haveFirst = true
				}
				lit.Reset()
				continue
			}
			lit.WriteByte(c)
			continue
		}
		switch {
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				return out
			}
			i += 2 + j + 1
		case c == '\'':
			inQuote = true
			lit.Reset()
		case c == '(':
			depth++
			if depth == 1 {
				tupleStarted = true
				haveFirst = false
			}
		case c == ')':
			depth--
			if depth == 0 {
				tupleStarted = false
			}
		case c == ';' && depth == 0:
			return out
		}
	}
	return out
}

// TestDetectorCensusMatchesTheMigratedDatabase is the ratchet.
//
// Set equality in both directions against the live static_policies population
// of a migrated database, plus a field-by-field comparison of every derived
// column against the compiler's record. It refuses an empty census and an
// empty capture: both were planted and both go red.
func TestDetectorCensusMatchesTheMigratedDatabase(t *testing.T) {
	dir := detectorCaptureDir(t)
	rows := loadDetectorCaptureRows(t, dir)
	census := loadDetectorCensus(t)

	rep, err := legacycompile.Compile(rows, legacycompile.Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	recByPolicy := map[string]legacycompile.Record{}
	for _, rec := range rep.Records {
		if rec.Source.Table == "static_policies" {
			recByPolicy[rec.Source.PolicyID] = rec
		}
	}

	var static []legacycompile.RawRow
	for _, r := range rows {
		if r.Table == "static_policies" {
			static = append(static, r)
		}
	}
	// Anti-vacuity on the DATABASE side. A capture that lost the table
	// reconciles zero rows against a census this test would then declare
	// wholly stale - which is the right answer for the wrong reason. Say so
	// here instead.
	if len(static) == 0 {
		t.Fatalf("the capture holds no static_policies rows; a comparison against nothing is not evidence")
	}

	assertToleratedMigrationFailures(t, dir)

	seededBy, _ := censusSeedProvenance(t)
	bearing := loadValidatorBearingPlanes(t)

	inDB := map[string]legacycompile.RawRow{}
	for _, r := range static {
		inDB[captureColumn(r, "policy_id")] = r
	}
	inCensus := map[string]detectorCensusRow{}
	for _, c := range census {
		inCensus[c.PolicyID] = c
	}

	var missingFromCensus, missingFromDB []string
	for id := range inDB {
		if _, ok := inCensus[id]; !ok {
			missingFromCensus = append(missingFromCensus, id)
		}
	}
	for id := range inCensus {
		if _, ok := inDB[id]; !ok {
			missingFromDB = append(missingFromDB, id)
		}
	}
	sort.Strings(missingFromCensus)
	sort.Strings(missingFromDB)

	if len(missingFromCensus) > 0 {
		t.Errorf("%d live static_policies row(s) are NOT in the census: %v\n"+
			"A seeded detection row with no class is a v11 scope item nobody counted.",
			len(missingFromCensus), missingFromCensus)
	}
	if len(missingFromDB) > 0 {
		t.Errorf("%d census row(s) have NO live database row: %v\n"+
			"Either the row was superseded - move it to detectors_census_superseded.tsv - or the census "+
			"describes a substrate no deployment has.", len(missingFromDB), missingFromDB)
	}

	mismatches := 0
	for id, raw := range inDB {
		want, ok := inCensus[id]
		if !ok {
			continue
		}
		rec, ok := recByPolicy[id]
		if !ok {
			t.Errorf("%s: the compiler produced no record for a captured row; legacycompile guarantees "+
				"exactly one record per row, so this is a compiler or capture defect", id)
			continue
		}
		got := derivedCensusRow(raw, rec, seededBy, bearing)
		got.Exceptions = want.Exceptions // the one reviewed, non-derived column

		gf, wf := got.fields(), want.fields()
		for i := range gf {
			if gf[i] != wf[i] {
				mismatches++
				t.Errorf("%s: column %s: census %q, derived from the database and the compiler %q",
					id, detectorCensusColumns[i], wf[i], gf[i])
			}
		}
	}

	// Counts, including the zero buckets.
	byClass := map[string]int{classPattern: 0, classAlgorithmic: 0, classNotADetector: 0}
	// Emit is a SET per row, so it is counted by MEMBERSHIP. Counting the
	// rendered string instead put the twelve "Deny|Signal" rows in their own
	// bucket and reported eleven Denies for a corpus that denies on
	// twenty-three rows - an undercount of the strongest emit, which is the
	// one number nobody should have to reconstruct.
	byEmit := map[string]int{emitDeny: 0, emitEscalate: 0, emitSignal: 0, emitNone: 0}
	divergent := 0
	byDisp := map[string]int{"compiled": 0, "preserved_defect": 0, "uncompilable": 0}
	for _, c := range census {
		byClass[c.Class]++
		members := strings.Split(c.Emit, "|")
		if len(members) > 1 {
			divergent++
		}
		for _, m := range members {
			byEmit[m]++
		}
		byDisp[c.Disposition]++
	}
	// The denominator reconciliation, PRINTED rather than narrated. The
	// 70/22/9 split appears in the design doc, the CHANGELOG and the PR body;
	// until this bucket existed it was the one set of numbers in all three
	// that no test emitted. Every combination is printed, including the empty
	// ones, so a population moving between tiers is visible rather than
	// arithmetic somebody has to redo.
	byTier := map[string]int{}
	for _, c := range census {
		byTier[c.Tier+" enabled="+c.Enabled]++
	}
	for _, k := range []string{"system enabled=true", "system enabled=false",
		"tenant enabled=true", "tenant enabled=false"} {
		t.Logf("  %-22s %3d", k, byTier[k])
	}
	t.Logf("static_policies in the database: %d", len(static))
	t.Logf("census rows: %d", len(census))
	for _, k := range []string{classPattern, classAlgorithmic, classNotADetector} {
		t.Logf("  class %-14s %3d", k, byClass[k])
	}
	for _, k := range []string{emitDeny, emitEscalate, emitSignal, emitNone} {
		t.Logf("  emit(member) %-9s %3d", k, byEmit[k])
	}
	t.Logf("  rows whose emit DIVERGES across planes: %d", divergent)
	for _, k := range []string{"compiled", "preserved_defect", "uncompilable"} {
		t.Logf("  disposition %-14s %3d", k, byDisp[k])
	}
	t.Logf("rows only in the database: %d; rows only in the census: %d; field mismatches: %d",
		len(missingFromCensus), len(missingFromDB), mismatches)
}

// preCanonicalSeeds are the migrations that seeded the FIRST generation of
// detection rows, before 031 re-seeded the platform's built-ins under `sys_*`
// identifiers with corrected patterns and the `system` tier (#3323).
//
// A live row seeded only by one of these is a pre-canonical row by
// construction, which is the derivable signal the ledger is held to. It is not
// a judgement about the row's name or its category spelling.
var preCanonicalSeeds = map[string]bool{
	"010_policy_tables.sql":       true,
	"014_eu_ai_act_templates.sql": true,
}

// TestSupersessionLedgerIsCompleteAndHonest holds
// detectors_census_superseded.tsv to the migrated database.
//
// The ledger's semantics are the ones the database actually has, and they are
// NOT "seeded then deleted". #3323 is OPEN: no forward migration has ever
// deleted a static_policies row - `DELETE FROM static_policies` appears only in
// `*_down.sql` files - so every superseded row is still LIVE and still
// enforced alongside the row that superseded it. A ledger built on the
// absence of a row would therefore have been empty and would have reported the
// supersession problem as solved.
//
// Three things are checked, all against the capture:
//
//  1. every superseding id named in the ledger is LIVE, so the cleanup #3323
//     asks for cannot silently drop coverage;
//  2. `still_live` matches the capture, so the day #3323 lands the ledger goes
//     red and has to be re-stated rather than quietly becoming wrong;
//  3. every live row seeded ONLY by a pre-canonical migration appears in the
//     ledger - the both-ways half, so a first-generation row cannot be left
//     out of the supersession story.
func TestSupersessionLedgerIsCompleteAndHonest(t *testing.T) {
	dir := detectorCaptureDir(t)
	rows := loadDetectorCaptureRows(t, dir)

	live := map[string]bool{}
	for _, r := range rows {
		if r.Table == "static_policies" {
			live[captureColumn(r, "policy_id")] = true
		}
	}
	if len(live) == 0 {
		t.Fatalf("the capture holds no static_policies rows; every ledger claim below would be vacuous")
	}

	recs, err := readCensusTSV(detectorCensusSupersededPath, detectorCensusSupersededColumns)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(recs) == 0 {
		t.Fatalf("%s holds no rows; #3323 documents at least five superseded static rows, so an empty "+
			"ledger is a lost artifact rather than a clean result", detectorCensusSupersededPath)
	}

	declared := map[string]bool{}
	ledgerSeededBy := map[string]string{}
	superseded := 0
	for _, f := range recs {
		id, seededBy, supersededBy, stillLive, tracking, note := f[0], f[1], f[2], f[3], f[4], f[5]
		declared[id] = true

		// seeded_by and tracking were declarations nothing read. seeded_by
		// duplicates the census's seed_migration for the same policy_id - the
		// redundancy is tolerable only if something holds the two equal, so
		// this does. tracking is either "-" or an issue reference.
		ledgerSeededBy[id] = seededBy
		if tracking != "-" && !strings.HasPrefix(tracking, "#") {
			t.Errorf("%s: tracking %q is neither \"-\" nor an issue reference", id, tracking)
		}

		if !live[id] && stillLive == "yes" {
			t.Errorf("%s: the ledger says still_live=yes and the migrated database does not hold it", id)
		}
		if live[id] && stillLive != "yes" {
			t.Errorf("%s: the ledger says still_live=%q and the migrated database DOES hold it. "+
				"If #3323 has landed, restate the ledger; do not leave a stale claim.", id, stillLive)
		}
		// A ledger row is one of two things, and both must be stated. Either
		// it names a superseder - every one of which must be live, or the
		// deletion #3323 asks for would drop coverage - or it declares itself
		// a first-class pre-canonical row, which needs a reason, because
		// "no superseder" with no explanation is how a row nobody looked at
		// enters the ledger.
		if supersededBy == "-" || supersededBy == "" {
			if strings.TrimSpace(note) == "" || note == "-" {
				t.Errorf("%s: names no superseder and carries no note; a row claiming to be first-class "+
					"pre-canonical must say why", id)
			}
			continue
		}
		superseded++
		for _, sup := range strings.Split(supersededBy, ",") {
			sup = strings.TrimSpace(sup)
			if !live[sup] {
				t.Errorf("%s: names superseder %q, which is NOT live in the migrated database. "+
					"Deleting the superseded row would drop coverage.", id, sup)
			}
		}
	}

	// Hold seeded_by to the census's own seed_migration column.
	for _, c := range loadDetectorCensus(t) {
		want, ok := ledgerSeededBy[c.PolicyID]
		if !ok {
			continue
		}
		if want != c.SeedMigration {
			t.Errorf("%s: the ledger says seeded_by %q, the census says seed_migration %q",
				c.PolicyID, want, c.SeedMigration)
		}
	}

	_, seededIDs := censusSeedProvenance(t)
	var undeclared []string
	for id, files := range seededIDs {
		if !live[id] || declared[id] {
			continue
		}
		preOnly := true
		for _, f := range files {
			if !preCanonicalSeeds[f] {
				preOnly = false
			}
		}
		if preOnly {
			undeclared = append(undeclared, id+" (seeded by "+strings.Join(files, ",")+")")
		}
	}
	sort.Strings(undeclared)
	if len(undeclared) > 0 {
		t.Errorf("%d live row(s) seeded only by a pre-canonical migration are absent from the "+
			"supersession ledger:\n  %s\nEither they are superseded and the ledger must say by what, "+
			"or they are first-class rows and the ledger must say that too.",
			len(undeclared), strings.Join(undeclared, "\n  "))
	}
	t.Logf("ledger rows: %d (%d with a named superseder, %d first-class pre-canonical); "+
		"pre-canonical live rows not ledgered: %d",
		len(recs), superseded, len(recs)-superseded, len(undeclared))

	// THE STRENGTH INVERSION, ASSERTED RATHER THAN NARRATED.
	//
	// #3323 asks for a cleanup migration deleting the rows superseded by 031,
	// on the stated ground that "nothing is dropped by removing them", and its
	// acceptance asks for a per-pair PATTERN test. The action is not mentioned.
	// Migration 067 relaxed the system defaults to `warn` by category and by an
	// explicit sys_pii_* id list, and the pre-canonical rows carry neither the
	// categories nor the ids that clause names - so each superseded row is
	// STRONGER than the row that superseded it, and deleting it lowers
	// enforcement.
	//
	// This is checked, not described, because it is the finding a future
	// cleanup migration most needs to trip over. It reads the LEGACY ACTION of
	// both sides out of the census, which is derived from the database.
	action := map[string]string{}
	tier := map[string]string{}
	for _, c := range loadDetectorCensus(t) {
		action[c.PolicyID] = c.LegacyAction
		tier[c.PolicyID] = c.Tier
	}
	inversions, pairs := 0, 0
	for _, f := range recs {
		id, supersededBy := f[0], f[2]
		if supersededBy == "-" || supersededBy == "" {
			continue
		}
		for _, sup := range strings.Split(supersededBy, ",") {
			sup = strings.TrimSpace(sup)
			if action[id] == "" || action[sup] == "" {
				t.Errorf("%s / %s: one of the pair is absent from the census, so the pair cannot be compared",
					id, sup)
				continue
			}
			pairs++
			// DIRECTION, not merely inequality. Inequality alone is satisfied
			// by the opposite of the finding - making the SUPERSEDER stronger
			// would pass a difference check while the ledger note, the design
			// doc and #3323 all say the superseded row is the stronger one.
			//
			// The direction is stated in migration 067's own terms rather
			// than through a restrictiveness ranking, for a reason narrower
			// than "no ranking exists" - one DOES:
			// platform/agent.ActionRestrictiveness ranks block(5) >
			// require_approval(4) > redact(3) > warn(2) > log(1), and
			// legacycompile/shadow mirrors it under
			// TestRestrictivenessMirrorsTheEngine. What
			// contract/obligation.go refuses is a scale for OBLIGATION
			// composition, which is a different question.
			//
			// The ranking is not used here because it would make this
			// assertion depend on an ordering rather than on the event that
			// produced the finding. Migration 067 relaxed the system defaults
			// TO `warn`, by category and by an explicit sys_pii_* id list, and
			// the pre-canonical rows matched neither clause. Naming that makes
			// the check falsifiable against a specific migration and makes the
			// failure message tell a reader which ledger note went stale;
			// "rank(superseded) > rank(superseder)" would stay green if both
			// sides moved together.
			switch {
			case action[sup] != "warn":
				t.Errorf("%s -> %s: the superseder's action is %q, not \"warn\". Migration 067 relaxed "+
					"every superseder to warn, and the ledger note for %s is written on that basis. "+
					"Restate the note.", id, sup, action[sup], id)
			case action[id] == "warn":
				t.Errorf("%s -> %s: the superseded row's action is also \"warn\", so it is no longer "+
					"stronger than its superseder and the ledger note claiming it is has gone stale.",
					id, sup)
			default:
				inversions++
			}
		}
	}
	if pairs == 0 {
		t.Error("no superseded/superseder pair was comparable; the strength check verified nothing")
	}
	if inversions != pairs {
		t.Errorf("%d of %d superseded/superseder pairs still show the superseded row as the stronger one; "+
			"the ledger notes claim all of them do", inversions, pairs)
	}
	t.Logf("superseded/superseder pairs: %d, of which the superseded row is the STRONGER "+
		"(superseder relaxed to warn by migration 067, superseded row not): %d", pairs, inversions)

	// The tenant-tier population §2.1 of the design doc quotes.
	tenantStrong := 0
	for id, a := range action {
		if tier[id] == "tenant" && (a == "block" || a == "redact") {
			tenantStrong++
		}
	}
	t.Logf("tenant-tier rows carrying block/redact: %d; ledgered with a named superseder: %d", tenantStrong, superseded)
}

// TestGenerateDetectorCensus regenerates both fixtures from a real capture.
// It is not a check and is skipped unless explicitly asked, because a test
// that rewrites the artifact it verifies can never fail.
func TestGenerateDetectorCensus(t *testing.T) {
	if os.Getenv("AXONFLOW_DETECTOR_CENSUS_UPDATE") == "" {
		t.Skip("set AXONFLOW_DETECTOR_CENSUS_UPDATE=1 with AXONFLOW_LEGACY_CAPTURE_DIR to regenerate the census")
	}
	dir := detectorCaptureDir(t)
	rows := loadDetectorCaptureRows(t, dir)
	rep, err := legacycompile.Compile(rows, legacycompile.Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	recByPolicy := map[string]legacycompile.Record{}
	for _, rec := range rep.Records {
		if rec.Source.Table == "static_policies" {
			recByPolicy[rec.Source.PolicyID] = rec
		}
	}
	seededBy, seededIDs := censusSeedProvenance(t)
	bearing := loadValidatorBearingPlanes(t)

	existing := map[string]string{}
	if recs, err := readCensusTSV(detectorCensusPath, detectorCensusColumns); err == nil {
		for _, f := range recs {
			existing[f[0]] = f[len(f)-1]
		}
	}

	var out []detectorCensusRow
	live := map[string]bool{}
	for _, r := range rows {
		if r.Table != "static_policies" {
			continue
		}
		id := captureColumn(r, "policy_id")
		live[id] = true
		c := derivedCensusRow(r, recByPolicy[id], seededBy, bearing)
		c.Exceptions = existing[id]
		if c.Exceptions == "" {
			c.Exceptions = "-"
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PolicyID < out[j].PolicyID })

	var b strings.Builder
	b.WriteString(strings.Join(detectorCensusColumns, "\t") + "\n")
	for _, c := range out {
		b.WriteString(strings.Join(c.fields(), "\t") + "\n")
	}
	if err := os.WriteFile(detectorCensusPath, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("writing the census: %v", err)
	}
	t.Logf("wrote %d row(s) to %s", len(out), detectorCensusPath)

	// Candidate ledger rows: live rows seeded only by a pre-canonical
	// migration. The superseder and the note are a REVIEWED judgement and are
	// left as "?" for a human to complete; the generator never invents one.
	var sup []string
	for id, files := range seededIDs {
		if !live[id] {
			continue
		}
		preOnly := true
		for _, f := range files {
			if !preCanonicalSeeds[f] {
				preOnly = false
			}
		}
		if preOnly {
			sup = append(sup, id+"\t"+strings.Join(files, ",")+"\t?\tyes\t?\t?")
		}
	}
	sort.Strings(sup)
	t.Logf("candidate supersession-ledger rows (%d):\n%s", len(sup), strings.Join(sup, "\n"))
}
