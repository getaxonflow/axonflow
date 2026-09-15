// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/contract"
)

// THE CENSUS'S RUNTIME CONSUMER (#3884)
//
// `detectors_census.tsv` has been in the tree since #3827 and, in that issue's
// own words, "the census has no runtime consumer - it describes the corpus; it
// does not move it". This file is that consumer: it parses the shipped census
// into `DetectorRecord`s and `SeedShippedDetectors` registers them, so a row
// the census describes and nothing registers becomes a build failure rather
// than a description nobody reads.
//
// # THE ONE DERIVATION IN HERE THAT IS EASY TO GET BACKWARDS
//
// The census's `validator_planes` column is a property of the PLANE, not of
// the detector: it names the planes whose evaluator is validator-bearing at
// all. `DetectorRecord.GatingPlanes` is a property of the DETECTOR: the planes
// on which THIS detector's implementation gates every evaluation.
//
// For an algorithmic detector the two coincide, because the implementation IS
// the validator the column is about. For a PATTERN detector they do not
// coincide at all - the pattern is what every engine runs, so a pattern gates
// on every plane it is evaluated on. Copying `validator_planes` onto a pattern
// record would report the pattern detectors as ungated wherever that column
// leaves a plane out - as it left out `proxy_tier`, the tier plane #4253
// retired, before #3963 - which is false, and would make
// `CheckDetectorSelection` refuse eighty-one correct policies while the twenty
// that genuinely need refusing look the same as the rest.
//
// `deriveGatingPlanes` is where the split lives and it switches on the class.

// DetectorCensusFile is the checked-in census, embedded so the registry seeds
// itself from the artifact that ships rather than from a copy on the runner's
// disk. It is the same file `platform/shared/policy/detector_census_test.go`
// holds to a migrated database, read from the other side of the module
// boundary.
//
//go:embed detectors_census.tsv
var DetectorCensusFile string

// detectorCensusHeader is the exact expected header row, in order. A parse
// that tolerated a reordered header would compare two different columns and
// report the answer to a question nobody asked.
var detectorCensusHeader = []string{
	"policy_id", "name", "category", "tier", "enabled",
	"class", "impl_site", "legacy_action", "severity",
	"adr065_emit", "obligations", "posture_lever",
	"disposition", "disposition_reasons", "planes", "validator_planes",
	"seed_migration", "exceptions",
}

// shippedDetectorVersion is the implementation version every shipped detector
// registers at.
//
// It is 1 for all of them because v11 is the first release in which a detector
// has a version at all: before this registry there was no artifact a document
// could pin, so there is no earlier version for anything to be. A bump is a
// behaviour change to a named implementation and arrives with the evidence
// that proves it, which is why this is a constant here rather than a column
// somebody edits.
const shippedDetectorVersion = 1

// shippedAlgorithmicEvidence is the test that drives every algorithmic
// detector's implementation against the running binary.
//
// ONE NAME FOR ALL TWENTY, AND THAT IS THE POINT. The obvious alternative - a
// per-detector evidence column - is a hand-kept list, and a hand-kept list is
// one entry short the day a twenty-first algorithmic row is seeded. The test
// named here ENUMERATES the algorithmic rows from this same census and
// requires a separating witness for each, so a new row is covered by
// construction and an uncovered row is a red test rather than a missing
// column.
//
// `TestEveryAlgorithmicDetectorNamesEvidenceThatExists` holds this name to a
// file and a symbol that are actually in the tree.
const shippedAlgorithmicEvidence = "platform/shared/policy/detector_implementation_derivation_test.go::TestEveryAlgorithmicDetectorIsGatedByItsImplementation"

// mixedPlaneSuffix marks a plane whose name covers call sites that do not
// agree about whether the implementation gates.
const mixedPlaneSuffix = "(mixed)"

// CensusRow is one parsed census row, before it becomes a record.
//
// It is exported because the corpus builder and the before/after harness both
// need the legacy facts - the stored action, the disposition, the seed
// migration - that a `DetectorRecord` deliberately does not carry. A record
// describes a detector; a row describes where that detector came from.
type CensusRow struct {
	PolicyID     string
	Name         string
	Category     string
	Tier         string
	Enabled      bool
	Class        DetectorClass
	ImplSite     string
	LegacyAction string
	Severity     string
	Emit         []Emit
	Obligations  []contract.ObligationType
	// PostureLever is "-" on every row: no environment variable sets a
	// detection action since #3961. The column is kept so a lever reappearing
	// is a diff in the census and a red in the policy package's census test.
	PostureLever       string
	Disposition        string
	DispositionReasons []string
	Planes             []string
	ValidatorPlanes    []string
	MixedPlanes        []string
	SeedMigration      string
	Exception          string
	Line               int
}

// SystemTier reports whether the row is part of the immutable system-tier
// subset. It is the line the corpus split falls on: a system-tier row is
// deployment-invariant and can live in a build-invariant artifact; a
// tenant-tier row is customer-editable and cannot.
func (r CensusRow) SystemTier() bool { return r.Tier == "system" }

// ParseDetectorCensus parses the census.
//
// It is strict about shape for the reason `ParseLegacyPlanes` is: a shifted
// column has to be a parse error rather than a value landing quietly in the
// wrong field. An empty cell is always an error - the census writes "no value"
// as "-" - so "this row has no obligations" is something somebody wrote
// rather than something a blank was read as.
func ParseDetectorCensus(content string) ([]CensusRow, error) {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("registry: the detector census has no data rows")
	}
	header := strings.Split(lines[0], "\t")
	if len(header) != len(detectorCensusHeader) {
		return nil, fmt.Errorf("registry: the detector census header has %d columns, expected %d",
			len(header), len(detectorCensusHeader))
	}
	for i, want := range detectorCensusHeader {
		if header[i] != want {
			return nil, fmt.Errorf("registry: detector census header column %d is %q, expected %q", i+1, header[i], want)
		}
	}
	var out []CensusRow
	seen := map[string]int{}
	for n, line := range lines[1:] {
		lineNo := n + 2
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cells := strings.Split(line, "\t")
		if len(cells) != len(detectorCensusHeader) {
			return nil, fmt.Errorf("registry: detector census line %d has %d columns, expected %d",
				lineNo, len(cells), len(detectorCensusHeader))
		}
		for i, c := range cells {
			if c == "" {
				return nil, fmt.Errorf("registry: detector census line %d column %q is empty; the census writes an absent value as \"-\"",
					lineNo, detectorCensusHeader[i])
			}
			if strings.TrimSpace(c) != c {
				return nil, fmt.Errorf("registry: detector census line %d column %q has surrounding whitespace",
					lineNo, detectorCensusHeader[i])
			}
		}
		row, err := censusRowFrom(cells, lineNo)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[row.PolicyID]; dup {
			return nil, fmt.Errorf("registry: detector census line %d repeats policy_id %q from line %d; the census is keyed by policy_id and a duplicate makes every lookup ambiguous",
				lineNo, row.PolicyID, prev)
		}
		seen[row.PolicyID] = lineNo
		out = append(out, row)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("registry: the detector census parsed to zero rows")
	}
	return out, nil
}

func censusRowFrom(cells []string, lineNo int) (CensusRow, error) {
	class, err := ParseDetectorClass(cells[5])
	if err != nil {
		return CensusRow{}, fmt.Errorf("registry: detector census line %d: %w", lineNo, err)
	}
	enabled, err := parseCensusBool(cells[4], lineNo)
	if err != nil {
		return CensusRow{}, err
	}
	emit, err := parseEmitSet(cells[9], lineNo)
	if err != nil {
		return CensusRow{}, err
	}
	obligations, err := parseObligationSet(cells[10], lineNo)
	if err != nil {
		return CensusRow{}, err
	}
	planes := splitCensusList(cells[14])
	// AN ENABLED ROW EVALUATES SOMEWHERE AND A DISABLED ROW EVALUATES NOWHERE,
	// AND BOTH DIRECTIONS ARE ASSERTED.
	//
	// The nine rows with no plane are the disabled integration seeds
	// (migrations 060/064), excluded by the legacy readers' own predicate.
	// They must import as DISABLED documents rather than vanish - #3827's
	// handoff is explicit about that - so an empty plane list is legitimate
	// there and only there. The two facts correlate perfectly in the shipped
	// census (9 disabled / 9 planeless, 92 enabled / 92 with planes), so this
	// is a check rather than a tolerance: an enabled row that evaluates
	// nowhere is a control nobody enforces while the portal lists it, and a
	// disabled row that names planes is a plane list nothing derived.
	if enabled && len(planes) == 0 {
		return CensusRow{}, fmt.Errorf("registry: detector census line %d is enabled and declares no plane; a control nothing evaluates while the portal lists it is the defect this registry exists to make visible", lineNo)
	}
	if !enabled && len(planes) > 0 {
		return CensusRow{}, fmt.Errorf("registry: detector census line %d is disabled and declares plane(s) %v; a disabled row is excluded by the legacy readers' own predicate and evaluates nowhere, so a plane list here was not derived from the corpus", lineNo, planes)
	}
	gating, mixed := splitValidatorPlanes(cells[15])
	row := CensusRow{
		PolicyID: cells[0], Name: cells[1], Category: cells[2], Tier: cells[3], Enabled: enabled,
		Class: class, ImplSite: cells[6], LegacyAction: cells[7], Severity: cells[8],
		Emit: emit, Obligations: obligations, PostureLever: cells[11],
		Disposition: cells[12], DispositionReasons: splitCensusList(cells[13]),
		Planes: planes, ValidatorPlanes: gating, MixedPlanes: mixed,
		SeedMigration: cells[16], Exception: cells[17], Line: lineNo,
	}
	return row, nil
}

func parseCensusBool(s string, lineNo int) (bool, error) {
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("registry: detector census line %d: enabled is %q, expected \"true\" or \"false\"", lineNo, s)
	}
}

// splitCensusList reads a comma-separated cell, with "-" meaning empty.
func splitCensusList(s string) []string {
	if s == "-" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// splitValidatorPlanes reads the validator_planes cell into the fully
// validator-bearing planes and the mixed ones.
func splitValidatorPlanes(s string) (gating, mixed []string) {
	for _, p := range splitCensusList(s) {
		if name, found := strings.CutSuffix(p, mixedPlaneSuffix); found {
			mixed = append(mixed, name)
			continue
		}
		gating = append(gating, p)
	}
	sort.Strings(gating)
	sort.Strings(mixed)
	return gating, mixed
}

// parseEmitSet reads the census's emit rendering, which is a SET separated by
// "|" and never collapsed.
func parseEmitSet(s string, lineNo int) ([]Emit, error) {
	if s == "-" {
		return nil, nil
	}
	var out []Emit
	for _, part := range strings.Split(s, "|") {
		e := Emit(part)
		if !e.IsValid() {
			return nil, fmt.Errorf("registry: detector census line %d: emit %q is not Signal, Deny or Escalate", lineNo, part)
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func parseObligationSet(s string, lineNo int) ([]contract.ObligationType, error) {
	if s == "-" {
		return nil, nil
	}
	declared := map[contract.ObligationType]bool{}
	for _, t := range contract.AllObligationTypes() {
		declared[t] = true
	}
	var out []contract.ObligationType
	for _, part := range strings.Split(s, ",") {
		t := contract.ObligationType(part)
		if !declared[t] {
			return nil, fmt.Errorf("registry: detector census line %d: obligation %q is not a type the contract declares", lineNo, part)
		}
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// deriveGatingPlanes answers "on which planes does THIS detector's
// implementation gate every evaluation", from the row's class and the census's
// per-plane validator column.
//
// See the file header: the census column is about the plane and the answer is
// about the detector, and for a pattern detector the two are different
// questions with different answers.
func deriveGatingPlanes(r CensusRow) (gating, mixed []string) {
	switch r.Class {
	case DetectorClassPattern:
		// The pattern IS the implementation and every legacy engine runs it
		// identically - `PatternEvaluator.Evaluate` compiles and matches, as
		// the tier engine's `evaluateFirstMatch` did until #4253 retired it. So
		// a pattern gates wherever it is evaluated, with nothing mixed.
		return append([]string(nil), r.Planes...), nil
	case DetectorClassAlgorithmic:
		// The implementation is the validator, so it gates exactly where the
		// evaluator consults one - intersected with the planes this row is
		// evaluated on at all, because a plane in the validator column that
		// this row never reaches is not a gate this row has.
		on := map[string]bool{}
		for _, p := range r.Planes {
			on[p] = true
		}
		for _, p := range r.ValidatorPlanes {
			if on[p] {
				gating = append(gating, p)
			}
		}
		for _, p := range r.MixedPlanes {
			if on[p] {
				mixed = append(mixed, p)
			}
		}
		return gating, mixed
	default:
		// A not-a-detector row inspects no content, so there is nothing for an
		// implementation to gate. It is not a bare plane either: returning the
		// row's planes here would make BarePlanes empty and claim a gate.
		return nil, nil
	}
}

// deriveEditions answers which builds contain the implementation.
//
// A pattern is data seeded by `migrations/core`, which every build applies, so
// a pattern detector is in every build regardless of where its digest is
// recorded. An ALGORITHMIC detector is a Go symbol, and whether the community
// build contains it is a property of where that symbol lives.
//
// # THE FIRST VERSION OF THIS WAS FAIL-OPEN AND R3 DROVE IT
//
// It tested one prefix, `ee/`, described as "a path prefix rather than a list
// of enterprise symbols" - but a prefix on one root IS a list of one root, and
// this tree marks enterprise code three ways. Two of them were derived as
// present in the community build:
//
//	ee/platform/agent/rbi/pii_detector.go        enterprise only   (caught)
//	platform/orchestrator/ee/agents/x.go         enterprise only   (MISSED)
//	platform/shared/policy/validators_enterprise.go  enterprise only   (MISSED)
//
// The community sync strips all three: the rsync chain drops `ee/` wholesale,
// and the post-rsync pass deletes every Go file whose build constraint selects
// the enterprise build plus everything matching `*_enterprise.go`. The
// direction of the error is what makes it a defect rather than a rough edge -
// an enterprise-only implementation deriving as present in the community build
// is a bundle that may reference a detector that deployment's binaries do not
// contain.
//
// It is still a rule rather than a list, and the rule now matches the SYNC's
// own three mechanisms rather than one of them. The fourth mechanism a future
// reader should watch for is a build constraint that is not in the file name
// and not under an `ee/` path - `deriveEditions` cannot see a `//go:build`
// line, because the census records a file and a symbol rather than a parsed
// file, and that is stated here rather than left to be discovered.
func deriveEditions(r CensusRow) []Edition {
	if r.Class == DetectorClassAlgorithmic && enterpriseOnlyPath(r.ImplSite) {
		return []Edition{EditionEnterprise}
	}
	return []Edition{EditionCommunity, EditionEnterprise}
}

// enterpriseOnlyPath reports whether a path is one the community sync removes.
//
// The three mechanisms are the sync workflow's own: an `ee/` directory at any
// depth, and the `*_enterprise.go` file-name pattern.
func enterpriseOnlyPath(implSite string) bool {
	path, _, _ := strings.Cut(implSite, "::")
	if path == "" {
		return false
	}
	if strings.HasPrefix(path, "ee/") || strings.Contains(path, "/ee/") {
		return true
	}
	base := path
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	return strings.HasSuffix(base, "_enterprise.go") || strings.HasSuffix(base, "_enterprise_test.go")
}

// RecordFor projects one census row into a registry record.
func RecordFor(r CensusRow) DetectorRecord {
	gating, mixed := deriveGatingPlanes(r)
	rec := DetectorRecord{
		ID:                 DetectorID(r.PolicyID),
		Name:               r.Name,
		Class:              r.Class,
		Version:            shippedDetectorVersion,
		Category:           r.Category,
		DefaultEmit:        r.Emit,
		DefaultObligations: r.Obligations,
		Planes:             r.Planes,
		GatingPlanes:       gating,
		MixedPlanes:        mixed,
		Editions:           deriveEditions(r),
		Enabled:            r.Enabled,
	}
	if r.Exception != "-" {
		rec.Exception = r.Exception
	}
	switch r.Class {
	case DetectorClassPattern:
		rec.PatternDigest = r.ImplSite
		rec.Dialect = PatternDialectRE2
	case DetectorClassAlgorithmic:
		rec.Impl = r.ImplSite
		rec.ImplEvidence = []string{shippedAlgorithmicEvidence}
	}
	return rec
}

// ShippedCensus parses the embedded census.
func ShippedCensus() ([]CensusRow, error) { return ParseDetectorCensus(DetectorCensusFile) }

// ShippedDetectors projects the embedded census into registry records.
func ShippedDetectors() ([]DetectorRecord, error) {
	rows, err := ShippedCensus()
	if err != nil {
		return nil, err
	}
	out := make([]DetectorRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, RecordFor(r))
	}
	return out, nil
}

// SeedShippedDetectors registers every shipped detector into a catalog.
//
// It is the runtime consumer #3884 says the census does not have. A census row
// that will not register is a build-time failure naming the row and the
// reason, which is the mechanical form of "a row it describes that nothing
// consumes is a named failure".
func SeedShippedDetectors(c *Catalog) error {
	records, err := ShippedDetectors()
	if err != nil {
		return err
	}
	for _, rec := range records {
		if err := c.RegisterDetector(rec); err != nil {
			return fmt.Errorf("registry: seeding shipped detector %q: %w", rec.ID, err)
		}
	}
	return nil
}
