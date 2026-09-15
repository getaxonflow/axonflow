// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A pattern record that validates, used as the base for the negative cases so
// each one differs from a passing record in exactly the field under test.
func goodPatternDetector() DetectorRecord {
	return DetectorRecord{
		ID:            "test_pattern",
		Name:          "Test pattern",
		Class:         DetectorClassPattern,
		Version:       1,
		PatternDigest: "re2:sha256:0123456789ab",
		Dialect:       PatternDialectRE2,
		Planes:        []string{"decide", "openai_compatible"},
		GatingPlanes:  []string{"decide", "openai_compatible"},
		Editions:      []Edition{EditionCommunity, EditionEnterprise},
		Enabled:       true,
	}
}

func goodAlgorithmicDetector() DetectorRecord {
	return DetectorRecord{
		ID:           "test_algorithmic",
		Name:         "Test algorithmic",
		Class:        DetectorClassAlgorithmic,
		Version:      1,
		Impl:         "platform/shared/policy/validators.go::ValidateSSN",
		ImplEvidence: []string{shippedAlgorithmicEvidence},
		Planes:       []string{"decide", "policy_test", "openai_compatible"},
		GatingPlanes: []string{"decide"},
		MixedPlanes:  []string{"policy_test"},
		Editions:     []Edition{EditionCommunity, EditionEnterprise},
		Enabled:      true,
	}
}

func mustRegister(t *testing.T, c *Catalog, d DetectorRecord) {
	t.Helper()
	if err := c.RegisterDetector(d); err != nil {
		t.Fatalf("RegisterDetector(%s): %v", d.ID, err)
	}
}

// TestTheShippedCensusRegistersAsDetectors is the runtime-consumer check
// #3884 says the census does not have.
//
// It is not a count assertion. Every row must REGISTER, which means every row
// must pass the record validation, so a census row whose class, planes,
// implementation or edition cannot be projected into a record is a build
// failure naming the row - which is the mechanical form of "a row it describes
// that nothing consumes is a named failure".
func TestTheShippedCensusRegistersAsDetectors(t *testing.T) {
	c := NewCatalog(time.Now())
	if err := SeedShippedDetectors(c); err != nil {
		t.Fatalf("SeedShippedDetectors: %v", err)
	}
	rows, err := ShippedCensus()
	if err != nil {
		t.Fatalf("ShippedCensus: %v", err)
	}
	got := c.Detectors()
	if len(got) != len(rows) {
		t.Fatalf("the census holds %d row(s) and the catalog registered %d detector(s)", len(rows), len(got))
	}
	// Anti-vacuity: the loops below are over `got`, and an empty census would
	// pass every one of them having compared nothing. The floor is the seeded
	// population's order of magnitude rather than a number somebody picked.
	if len(got) < 50 {
		t.Fatalf("the catalog registered %d detector(s); the seeded corpus is three digits and a registry this small has lost most of it", len(got))
	}
	byID := map[DetectorID]bool{}
	for _, d := range got {
		byID[d.ID] = true
	}
	for _, r := range rows {
		if !byID[DetectorID(r.PolicyID)] {
			t.Errorf("census row %q registered no detector", r.PolicyID)
		}
	}
	// Catalog.Validate is not called here: it also requires a non-empty action
	// registry, which this catalog deliberately has none of, so its refusal
	// would be about actions rather than about detectors. The detector half of
	// the same rules is asserted directly, which is what this test is about.
	for _, d := range got {
		if f := d.Validate(); f.Blocking() {
			t.Errorf("%s: a registered record does not validate: %v", d.ID, f.Err())
		}
		if f := c.crossCheckDetector(d); f.Blocking() {
			t.Errorf("%s: a registered record fails its cross-check: %v", d.ID, f.Err())
		}
	}
}

// TestAPatternDetectorGatesOnEveryPlaneItRunsOn is the derivation that is
// easiest to get backwards, asserted over the whole shipped corpus.
//
// The census's `validator_planes` column is a property of the PLANE. A
// pattern's gating planes are a property of the DETECTOR, and they are all of
// them, because the pattern is what both legacy engines run. Copying the
// column onto a pattern record would report all 81 pattern detectors as
// ungated on any plane the column leaves out, as it left out the tier plane
// before #3963.
func TestAPatternDetectorGatesOnEveryPlaneItRunsOn(t *testing.T) {
	records, err := ShippedDetectors()
	if err != nil {
		t.Fatalf("ShippedDetectors: %v", err)
	}
	patterns := 0
	for _, d := range records {
		if d.Class != DetectorClassPattern {
			continue
		}
		patterns++
		if bare := d.BarePlanes(); len(bare) > 0 {
			t.Errorf("%s is a pattern detector and declares plane(s) %v on which its implementation does not gate", d.ID, bare)
		}
		if len(d.MixedPlanes) > 0 {
			t.Errorf("%s is a pattern detector and declares mixed plane(s) %v; a pattern cannot half-gate a plane", d.ID, d.MixedPlanes)
		}
	}
	if patterns == 0 {
		t.Fatal("no pattern detector in the shipped corpus; this check compared nothing")
	}
	t.Logf("checked %d pattern detector(s)", patterns)
}

// TestEveryAlgorithmicDetectorGatesOnEveryPlaneItRunsOn is what the previous
// test became when #3963 landed.
//
// It used to assert that all twenty algorithmic detectors run BARE on
// `proxy_tier`, and said in its own comment that it was expected to go red on
// the day the tier engine started resolving the validator. It did, with that
// message. This is the revisit it asked for, and the property is now the
// mirror image: `evaluateFirstMatch` consulted the row's validator, the census
// recorded `proxy_tier` as validator-bearing, and #4253 then retired that plane
// with the tier engine, so no shipped algorithmic detector has a bare plane.
//
// IT IS NOT VACUOUS DESPITE ASSERTING AN EMPTY SET. `BarePlanes()` is derived
// per record from the census's per-plane column, so this goes red the day any
// plane stops consulting the validator - which is the regression #3963 fixed
// returning. The count of algorithmic rows is asserted beside it so an emptied
// corpus cannot pass by having nothing to check.
func TestEveryAlgorithmicDetectorGatesOnEveryPlaneItRunsOn(t *testing.T) {
	records, err := ShippedDetectors()
	if err != nil {
		t.Fatalf("ShippedDetectors: %v", err)
	}
	algorithmic := 0
	for _, d := range records {
		if d.Class != DetectorClassAlgorithmic {
			continue
		}
		algorithmic++
		if bare := d.BarePlanes(); len(bare) > 0 {
			t.Errorf("%s is algorithmic and runs bare on %v. Since #3963 every static call site resolves the validator, so a "+
				"bare plane means either that wiring has been removed or the census has gone stale against it - and on a "+
				"bare plane the implementation (%s) is in the binary and not consulted, so the row over-blocks",
				d.ID, bare, d.Impl)
		}
		if !d.GatesOn("proxy_request") {
			t.Errorf("%s does not gate on proxy_request; /api/request's one pass reaches the shared engine's EvaluateRequest (proxyDetectorPass), which resolves the row's validator", d.ID)
		}
	}
	if algorithmic != 20 {
		t.Errorf("the shipped corpus holds %d algorithmic detector(s); the census's derivation found 20, and a change to that "+
			"number is a change to how many checksums are armed", algorithmic)
	}
}

// TestAnInspectionPolicyCannotSelectAPlaneThatCannotRunTheImplementation is
// the DoD's rule, driven on the real corpus.
func TestAnInspectionPolicyCannotSelectAPlaneThatCannotRunTheImplementation(t *testing.T) {
	c := NewCatalog(time.Now())
	if err := SeedShippedDetectors(c); err != nil {
		t.Fatalf("SeedShippedDetectors: %v", err)
	}

	// THE RULE IS EXERCISED ON A SYNTHETIC RECORD, AND THAT CHANGED WITH
	// #3963.
	//
	// Until the tier engine was wired to the validator resolver, this test
	// drove the bare-plane and mixed-plane arms with a REAL shipped detector -
	// `sys_pii_credit_card` on `proxy_tier` and on `policy_test`. Both arms are
	// now unreachable from the shipped corpus: every algorithmic detector gates
	// on every plane it runs on, and no census row is marked mixed.
	//
	// An invariant that cannot fail for the class under test is not evidence
	// about that class, so leaving the assertions pointed at real rows would
	// have left two refusal arms passing by having nothing to refuse. The rule
	// is still correct and is still the thing that stops a policy depending on
	// an algorithm a plane does not run, so it is driven here with records
	// built for the purpose - and the shipped corpus's own freedom from bare
	// and mixed planes is asserted SEPARATELY, below, as a different fact.
	bare := goodAlgorithmicDetector()
	bare.ID = "synthetic_bare"
	bare.Planes = []string{"decide", "openai_compatible"}
	bare.GatingPlanes = []string{"decide"}
	bare.MixedPlanes = []string{"policy_test"}
	bare.Planes = append(bare.Planes, "policy_test")
	mustRegister(t, c, bare)

	f := c.CheckDetectorSelection("synthetic_bare", []string{"openai_compatible"})
	if !f.Has(CodeDetectorPlaneCannotGate) {
		t.Errorf("selecting a detector on a plane its implementation does not gate was not refused: %v", f)
	}
	if !f.Blocking() {
		t.Errorf("the refusal is advisory; a policy that would be satisfied by a pattern match the algorithm rejects must not publish")
	}

	// The mixed plane carries its OWN code, because the remedy differs.
	f = c.CheckDetectorSelection("synthetic_bare", []string{"policy_test"})
	if !f.Has(CodeDetectorPlanePartiallyGates) {
		t.Errorf("selecting a mixed plane was not refused as partially gating: %v", f)
	}
	if f.Has(CodeDetectorPlaneCannotGate) {
		t.Errorf("a mixed plane must not be reported as a bare one; the two have different remedies: %v", f)
	}

	// AND THE SHIPPED CORPUS HAS NEITHER, which is a different claim from the
	// one above and is why they are asserted apart. Since #3963 no shipped
	// algorithmic detector has a bare plane and no census row is mixed; if that
	// stops being true, the arms above stop being synthetic and this says so.
	for _, d := range c.Detectors() {
		if d.ID == "synthetic_bare" {
			continue
		}
		if b := d.BarePlanes(); len(b) > 0 {
			t.Errorf("shipped detector %s runs bare on %v; the refusal arms above are exercised synthetically because the "+
				"corpus was believed to have none", d.ID, b)
		}
		if len(d.MixedPlanes) > 0 {
			t.Errorf("shipped detector %s declares mixed plane(s) %v; likewise", d.ID, d.MixedPlanes)
		}
	}

	// A real detector on a plane whose evaluator consults the validator.
	if f := c.CheckDetectorSelection("sys_pii_credit_card", []string{"decide"}); f.Blocking() {
		t.Errorf("selecting sys_pii_credit_card on decide was refused, and that plane's evaluator does consult the validator: %v", f.Err())
	}

	// A PATTERN detector on proxy_request is fine, and this is the case that
	// fails if the plane derivation is copied from the census column.
	if f := c.CheckDetectorSelection("drop_table_prevention", []string{"proxy_request"}); f.Blocking() {
		t.Errorf("selecting the pattern detector drop_table_prevention on proxy_request was refused; a pattern is what the engines "+
			"run, so it gates there. This is what fails when gating planes are copied from the census's per-PLANE column: %v", f.Err())
	}

	// An unregistered detector.
	if f := c.CheckDetectorSelection("no_such_detector", []string{"decide"}); !f.Has(CodeUnknownDetector) {
		t.Errorf("selecting an unregistered detector was not refused: %v", f)
	}

	// A plane the detector is not evaluated on at all is neither bare nor
	// mixed, and is its own answer.
	if f := c.CheckDetectorSelection("sys_pii_credit_card", []string{"wcp"}); !f.Has(CodeDetectorPlanesNotDeclared) {
		t.Errorf("selecting a plane the detector never runs on was not reported: %v", f)
	}
}

// TestDetectorRegistrationIsCreateOnly holds the same rule RegisterAction has,
// for the same reason.
func TestDetectorRegistrationIsCreateOnly(t *testing.T) {
	c := NewCatalog(time.Now())
	d := goodPatternDetector()
	mustRegister(t, c, d)
	// The re-registration is a RECLASSIFICATION, which is the case the rule
	// exists for: it would disarm an implementation on every document that
	// selects the detector, with no document edited.
	reclassified := goodAlgorithmicDetector()
	reclassified.ID = d.ID
	err := c.RegisterDetector(reclassified)
	if err == nil {
		t.Fatal("re-registering a detector under a different class was accepted; registration is create-only precisely so a " +
			"reclassification cannot happen silently")
	}
	if !strings.Contains(err.Error(), string(CodeAlreadyRegistered)) {
		t.Errorf("the refusal does not name ALREADY_REGISTERED: %v", err)
	}
	got, ok := c.Detector(d.ID)
	if !ok || got.Class != DetectorClassPattern {
		t.Errorf("the stored record changed under a refused registration: %+v", got)
	}
}

// TestTheCatalogDoesNotHandOutAWritableRecord is the clone rule, driven.
func TestTheCatalogDoesNotHandOutAWritableRecord(t *testing.T) {
	c := NewCatalog(time.Now())
	mustRegister(t, c, goodAlgorithmicDetector())

	got, _ := c.Detector("test_algorithmic")

	// IN-PLACE WRITES, NOT APPENDS, AND THAT DISTINCTION IS THE WHOLE TEST.
	//
	// The first version of this appended to the returned slices, and it PASSED
	// against a deliberately un-cloned accessor - because `append` on a slice
	// whose length equals its capacity allocates a new backing array, so the
	// catalog's copy was untouched whether or not anything was cloned. The
	// test proved nothing and said it had. An index assignment writes through
	// a shared backing array, which is the aliasing that actually reaches the
	// catalog.
	got.GatingPlanes[0] = "openai_compatible"
	got.MixedPlanes[0] = "wcp"
	got.Planes[0] = "wcp"

	again, _ := c.Detector("test_algorithmic")
	if again.GatesOn("openai_compatible") {
		t.Fatal("writing through a returned record's gating planes reached the catalog; a caller could then make a bare plane " +
			"claim a gate, past the check that would have refused it")
	}
	if !again.GatesOn("decide") {
		t.Fatal("the catalog's own gating planes were overwritten through a record it handed out")
	}
	if f := c.CheckDetectorSelection("test_algorithmic", []string{"openai_compatible"}); !f.Has(CodeDetectorPlaneCannotGate) {
		t.Error("the selection check stopped refusing openai_compatible after a caller wrote through its own copy")
	}

	// THE APPEND HALF WAS REMOVED, and saying why is the point. It was added
	// as "the other half of the hazard: an append reaches the catalog whenever
	// the slice has spare capacity", and R3 drove it against a catalog with
	// NO cloning on either store or read: the append still did not reach.
	// Appending to a `len 1, cap 4` slice writes index 1 of the backing array,
	// and the catalog's own slice still has length 1, so `GatesOn` - which
	// ranges over the length - cannot see it. It was a second assertion that
	// could not fail, sitting under a comment explaining that the FIRST one
	// had been replaced for exactly that reason. The index-assignment half
	// above is the whole of the real coverage.
}

// TestDetectorRecordValidationRefusesEachDefectByName drives every refusal
// arm, one field at a time from a record that passes.
func TestDetectorRecordValidationRefusesEachDefectByName(t *testing.T) {
	cases := []struct {
		name string
		want Code
		mut  func(*DetectorRecord)
	}{
		{"no class", CodeDetectorClassNotDeclared, func(d *DetectorRecord) { d.Class = DetectorClassUnspecified }},
		{"version zero", CodeDetectorVersionInvalid, func(d *DetectorRecord) { d.Version = 0 }},
		{"no edition", CodeEditionNotDeclared, func(d *DetectorRecord) { d.Editions = nil }},
		{"no dialect on a pattern", CodeDetectorDialectNotDeclared, func(d *DetectorRecord) { d.Dialect = PatternDialectUnspecified }},
		{"no pattern digest", CodeDetectorImplementationMissing, func(d *DetectorRecord) { d.PatternDigest = "" }},
		{"a pattern naming an implementation", CodeDetectorImplementationMissing, func(d *DetectorRecord) { d.Impl = "x.go::Y" }},
		{"a pattern naming evidence", CodeDetectorConformanceMissing, func(d *DetectorRecord) { d.ImplEvidence = []string{"x.go::Y"} }},
		{"enabled with no plane", CodeDetectorPlanesNotDeclared, func(d *DetectorRecord) { d.Planes, d.GatingPlanes = nil, nil }},
		{"disabled with planes", CodeDetectorPlanesNotDeclared, func(d *DetectorRecord) { d.Enabled = false }},
		{"gating on a plane it does not run on", CodeDetectorPlanesNotDeclared, func(d *DetectorRecord) {
			d.GatingPlanes = append(d.GatingPlanes, "wcp")
		}},
		{"a pattern with a bare plane", CodeDetectorPlanesNotDeclared, func(d *DetectorRecord) {
			d.GatingPlanes = []string{"decide"}
		}},
		{"an undeclared emit", CodeDetectorEmitNotDeclared, func(d *DetectorRecord) { d.DefaultEmit = []Emit{"Permit"} }},
		{"an empty identifier", CodeDetectorIdentifierInvalid, func(d *DetectorRecord) { d.ID = "" }},
		{"an untrimmed identifier", CodeDetectorIdentifierInvalid, func(d *DetectorRecord) { d.ID = " test_pattern" }},
	}
	// The base record must pass, or every case below is passing for the wrong
	// reason.
	if f := goodPatternDetector().Validate(); f.Blocking() {
		t.Fatalf("the base record does not validate, so no negative case below proves anything: %v", f.Err())
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := goodPatternDetector()
			tc.mut(&d)
			f := d.Validate()
			if !f.Has(tc.want) {
				t.Errorf("want %s, got %v", tc.want, f)
			}
		})
	}

	algorithmicCases := []struct {
		name string
		want Code
		mut  func(*DetectorRecord)
	}{
		{"no implementation", CodeDetectorImplementationMissing, func(d *DetectorRecord) { d.Impl = "" }},
		{"no evidence", CodeDetectorConformanceMissing, func(d *DetectorRecord) { d.ImplEvidence = nil }},
		{"evidence that is not path::Symbol", CodeDetectorConformanceMissing, func(d *DetectorRecord) {
			d.ImplEvidence = []string{"TestSomething"}
		}},
		{"a plane both gating and mixed", CodeDetectorPlanesNotDeclared, func(d *DetectorRecord) {
			d.MixedPlanes = []string{"decide"}
		}},
	}
	if f := goodAlgorithmicDetector().Validate(); f.Blocking() {
		t.Fatalf("the base algorithmic record does not validate: %v", f.Err())
	}
	for _, tc := range algorithmicCases {
		t.Run(tc.name, func(t *testing.T) {
			d := goodAlgorithmicDetector()
			tc.mut(&d)
			f := d.Validate()
			if !f.Has(tc.want) {
				t.Errorf("want %s, got %v", tc.want, f)
			}
		})
	}
}

// TestTheCensusParseRefusesAShapeItCannotTrust drives each parse refusal.
//
// A parse that padded a short row or tolerated a reordered header would
// compare two different columns and answer a question nobody asked, silently.
func TestTheCensusParseRefusesAShapeItCannotTrust(t *testing.T) {
	header := strings.Join(detectorCensusHeader, "\t")
	good := header + "\n" + strings.Join([]string{
		"row_a", "Row A", "pii-global", "system", "true",
		"pattern", "re2:sha256:0123456789ab", "warn", "high",
		"Signal", "notification", "-", // posture_lever: "-" on every row since #3961
		"compiled", "-", "decide,openai_compatible", "decide",
		"031_x.sql", "-",
	}, "\t") + "\n"
	if _, err := ParseDetectorCensus(good); err != nil {
		t.Fatalf("the good fixture does not parse, so every negative case below proves nothing: %v", err)
	}

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"a reordered header", strings.Replace(good, "policy_id\tname", "name\tpolicy_id", 1), "header column 1"},
		{"a short row", header + "\nrow_a\tRow A\n", "expected 18"},
		{"an empty cell", strings.Replace(good, "\tnotification\t-\t", "\tnotification\t\t", 1), "is empty"},
		{"a duplicate policy id", good + strings.Split(good, "\n")[1] + "\n", "repeats policy_id"},
		{"an undeclared class", strings.Replace(good, "\tpattern\t", "\tregex\t", 1), "not a declared detector class"},
		{"an undeclared emit", strings.Replace(good, "\tSignal\t", "\tPermit\t", 1), "not Signal, Deny or Escalate"},
		{"an undeclared obligation", strings.Replace(good, "\tnotification\t", "\tshout\t", 1), "not a type the contract declares"},
		{"enabled with no planes", strings.Replace(good, "\tdecide,openai_compatible\t", "\t-\t", 1), "enabled and declares no plane"},
		{"disabled with planes", strings.Replace(good, "\tsystem\ttrue\t", "\tsystem\tfalse\t", 1), "disabled and declares plane"},
		{"only a header", header + "\n", "has no data rows"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseDetectorCensus(tc.in)
			if err == nil {
				t.Fatalf("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason: want a message containing %q, got %v", tc.want, err)
			}
		})
	}
}

// TestEveryAlgorithmicDetectorNamesEvidenceThatExists is mechanism 1 of the
// registry's conformance machinery, applied across a module boundary.
//
// The evidence is a `path::Symbol` pair, and this resolves BOTH halves: the
// file must exist and the symbol must be declared in it. Checking only the
// file would pass on a renamed test, which is exactly the state the check is
// for - a record naming evidence that no longer runs.
func TestEveryAlgorithmicDetectorNamesEvidenceThatExists(t *testing.T) {
	root := repoRootFromRegistry(t)
	records, err := ShippedDetectors()
	if err != nil {
		t.Fatalf("ShippedDetectors: %v", err)
	}
	checked := 0
	for _, d := range records {
		for _, ev := range d.ImplEvidence {
			path, symbol, ok := strings.Cut(ev, "::")
			if !ok {
				t.Errorf("%s: evidence %q is not path::Symbol", d.ID, ev)
				continue
			}
			full := filepath.Join(root, path)
			b, err := os.ReadFile(full)
			if err != nil {
				// The community mirror stages platform/shared/policy, so this
				// file is present there too. An absence is a real finding
				// rather than a mirror artefact.
				t.Errorf("%s: evidence names %s, which cannot be read: %v", d.ID, path, err)
				continue
			}
			if !strings.Contains(string(b), "func "+symbol+"(") {
				t.Errorf("%s: evidence names %s in %s, and that file declares no such function. A record naming evidence that "+
					"does not run is a version nobody can check", d.ID, symbol, path)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no detector named any implementation evidence; this check compared nothing")
	}
	t.Logf("resolved %d evidence reference(s)", checked)
}

// repoRootFromRegistry walks up to the repository root.
func repoRootFromRegistry(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "platform", "decision", "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the repository root from the registry package")
	return ""
}

// TestAnEnterpriseOnlyImplementationIsDerivedAsEnterpriseOnly drives the
// edition derivation's other arm.
//
// No shipped detector's implementation is under `ee/` today, so that branch is
// unreachable from the census and would ship untested - which is how a
// derivation that has never run gets its first exercise on the day it decides
// whether a bundle may reference a detector a deployment's binaries do not
// contain.
func TestAnEnterpriseOnlyImplementationIsDerivedAsEnterpriseOnly(t *testing.T) {
	community := RecordFor(CensusRow{
		PolicyID: "x", Class: DetectorClassAlgorithmic, Enabled: true,
		ImplSite: "platform/shared/policy/validators.go::ValidateSSN",
		Planes:   []string{"decide"}, ValidatorPlanes: []string{"decide"},
	})
	if len(community.Editions) != 2 {
		t.Errorf("a community implementation derived editions %v; it is in every build", community.Editions)
	}
	// ALL THREE MECHANISMS THE COMMUNITY SYNC USES, not just the one that is
	// easy to think of. The first version of this derivation tested `ee/`
	// alone and derived the other two as present in the community build, which
	// is the fail-open direction; R3 drove it.
	for _, impl := range []string{
		"ee/platform/agent/rbi/pii_detector.go::ValidateSomething",
		"platform/orchestrator/ee/agents/validators.go::ValidateSomething",
		"platform/shared/policy/validators_enterprise.go::ValidateSomething",
	} {
		got := RecordFor(CensusRow{
			PolicyID: "y", Class: DetectorClassAlgorithmic, Enabled: true,
			ImplSite: impl,
			Planes:   []string{"decide"}, ValidatorPlanes: []string{"decide"},
		})
		if len(got.Editions) != 1 || got.Editions[0] != EditionEnterprise {
			t.Errorf("%s derived editions %v; the community sync removes that file, so the implementation is in the "+
				"enterprise build only and a community bundle referencing it would name a symbol that deployment's "+
				"binaries do not contain", impl, got.Editions)
		}
	}
	// A PATTERN whose digest is recorded under an enterprise path is still in
	// every build: a pattern is data seeded by migrations/core, which every
	// build applies. This case exists to hold the `Class` guard, so its
	// implementation site must be one that WOULD trip the path rule - the
	// earlier version used a plain `re2:` digest, which trips nothing, so the
	// guard it was written for was never exercised.
	pattern := RecordFor(CensusRow{
		PolicyID: "z", Class: DetectorClassPattern, Enabled: true,
		ImplSite: "ee/platform/policy/patterns.go::re2:sha256:0123456789ab",
		Planes:   []string{"decide"}, ValidatorPlanes: []string{"decide"},
	})
	if len(pattern.Editions) != 2 {
		t.Errorf("a pattern recorded under an enterprise path derived editions %v; the Class guard in deriveEditions is not "+
			"holding, and this is the case that exercises it", pattern.Editions)
	}
}

// TestSelectingAPlaneOnADisabledDetectorSaysSo keeps the refusal's REASON
// correct for the nine shipped rows that evaluate nowhere.
func TestSelectingAPlaneOnADisabledDetectorSaysSo(t *testing.T) {
	c := NewCatalog(time.Now())
	d := goodPatternDetector()
	d.ID = "disabled_one"
	d.Enabled = false
	d.Planes, d.GatingPlanes = nil, nil
	mustRegister(t, c, d)

	f := c.CheckDetectorSelection("disabled_one", []string{"decide"})
	if !f.Has(CodeDetectorPlanesNotDeclared) {
		t.Fatalf("selecting a plane on a disabled detector was not reported: %v", f)
	}
	if !strings.Contains(f[0].Message, "disabled") {
		t.Errorf("the refusal does not say the detector is disabled, so a reader is told the plane is wrong when the "+
			"detector is: %q", f[0].Message)
	}
}

// TestNoShippedImplementationIsBehindABuildConstraintTheDerivationCannotSee
// closes the gap `deriveEditions` names but cannot check itself.
//
// The edition derivation reads the implementation's PATH, so it sees `ee/` and
// `*_enterprise.go` and is blind to a `//go:build enterprise` line inside an
// otherwise community-looking file. The census records a file and a symbol
// rather than a parsed file, so the derivation cannot close that itself - but
// a TEST can open the file, and that is the difference between a named gap and
// an unguarded one.
//
// It fails the day a shipped implementation moves behind a build constraint,
// which is exactly when `Editions` would start lying in the fail-open
// direction: a community bundle referencing a symbol that binary does not
// contain.
func TestNoShippedImplementationIsBehindABuildConstraintTheDerivationCannotSee(t *testing.T) {
	root := repoRootFromRegistry(t)
	records, err := ShippedDetectors()
	if err != nil {
		t.Fatalf("ShippedDetectors: %v", err)
	}
	checked := 0
	for _, d := range records {
		if d.Class != DetectorClassAlgorithmic || d.Impl == "" {
			continue
		}
		path, _, ok := strings.Cut(d.Impl, "::")
		if !ok {
			t.Errorf("%s: implementation %q is not in path::Symbol form", d.ID, d.Impl)
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Errorf("%s: implementation names %s, which cannot be read: %v", d.ID, path, err)
			continue
		}
		checked++
		// The constraint is only ever in the first lines, before `package`.
		head := string(b)
		if i := strings.Index(head, "\npackage "); i > 0 {
			head = head[:i]
		}
		constrained := strings.Contains(head, "//go:build") && strings.Contains(head, "enterprise")
		derivedEnterpriseOnly := len(d.Editions) == 1 && d.Editions[0] == EditionEnterprise
		if constrained && !derivedEnterpriseOnly {
			t.Errorf("%s: its implementation %s carries an enterprise build constraint and the record derives editions %v. "+
				"deriveEditions reads the PATH and cannot see a build constraint, so this is the case it names as its own "+
				"blind spot - a community bundle would reference a symbol that binary does not contain", d.ID, path, d.Editions)
		}
		if !constrained && derivedEnterpriseOnly && !enterpriseOnlyPath(d.Impl) {
			t.Errorf("%s: derived as enterprise-only and its implementation %s is in neither an enterprise path nor behind an "+
				"enterprise build constraint", d.ID, path)
		}
	}
	if checked == 0 {
		t.Fatal("no algorithmic implementation was opened; this check compared nothing")
	}
	t.Logf("opened %d shipped implementation file(s); none is behind a build constraint the path rule cannot see", checked)
}
