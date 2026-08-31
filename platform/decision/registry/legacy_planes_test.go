package registry

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// repoRoot is this package's path back to the repository root, used to check
// that every evidence citation names a file that exists.
const repoRoot = "../../.."

// enterpriseSourceRe is the community sync's OWN definition of enterprise-only
// source: the build-constraint scan in .github/workflows/sync-community-repo.yml
// and .github/scripts/check-enterprise-leak.sh delete every Go file it matches
// before the mirror is published. Kept byte-identical at every site by
// tests/regression-test-required/enterprise_tag_regex_single_definition_test.sh.
var enterpriseSourceRe = regexp.MustCompile(`(?m)^//go:build enterprise|^// \+build enterprise`)

// evidenceIsEnterpriseOnly reports whether the sync's two DELETION mechanisms
// remove a cited file from the mirror: ee/ is excluded wholesale, *_enterprise.go
// and *_enterprise_test.go are deleted by name, and a file whose build
// constraint selects the enterprise build is deleted by the scan. The rsync
// chain's directory exclusions (platform/fptpcorpus/, platform/monitoring/,
// ...) are NOT modelled here; a citation into one of those is caught by the
// mirror simulation lane in test.yml rather than by this test.
func evidenceIsEnterpriseOnly(rel string) (bool, error) {
	if strippedByName(rel) {
		return true, nil
	}
	src, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		return false, err
	}
	return enterpriseSourceRe.Match(src), nil
}

// strippedByName is the half of the strip a path alone reveals.
func strippedByName(rel string) bool {
	return strings.HasPrefix(rel, "ee/") || strings.HasSuffix(rel, "_enterprise.go") || strings.HasSuffix(rel, "_enterprise_test.go")
}

// mirrorKnowsIsStripped reports whether the MIRROR can know, without the file,
// that the sync strips it. Only two facts survive the strip: the path's own
// name, and the edition column of the shipped call-site census
// (../legacycompile/legacy_call_sites.tsv), which platform/shared/policy's
// TestLegacyCallSiteCensusIsComplete verifies against each file's real build
// constraint in the enterprise tree on every run. Nothing else is evidence: a
// row's own edition says which BUILD the row describes, not which build
// carries the file, and enterprise-edition rows cite untagged community files.
func mirrorKnowsIsStripped(t *testing.T, rel string) bool {
	t.Helper()
	if strippedByName(rel) {
		return true
	}
	return censusEditions(t)[rel] == "enterprise"
}

// censusEditions reads file -> edition out of the shipped call-site census.
func censusEditions(t *testing.T) map[string]string {
	t.Helper()
	const path = "../legacycompile/legacy_call_sites.tsv"
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		t.Fatalf("%s is empty", path)
	}
	header := strings.Split(sc.Text(), "\t")
	fileCol, editionCol := -1, -1
	for i, h := range header {
		switch h {
		case "file":
			fileCol = i
		case "edition":
			editionCol = i
		}
	}
	if fileCol < 0 || editionCol < 0 {
		t.Fatalf("%s header %v lacks file/edition columns", path, header)
	}
	out := map[string]string{}
	for sc.Scan() {
		fields := strings.Split(strings.TrimSpace(sc.Text()), "\t")
		if len(fields) != len(header) {
			continue
		}
		out[fields[fileCol]] = fields[editionCol]
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if len(out) == 0 {
		t.Fatalf("%s has no rows", path)
	}
	return out
}

// treeIsCommunityMirror reports whether this checkout is the public mirror,
// which the sync produces without ee/.
func treeIsCommunityMirror() bool {
	_, err := os.Stat(filepath.Join(repoRoot, "ee"))
	return err != nil
}

// TestLegacyPlaneFixtureParsesAndIsComplete checks the checked-in table.
func TestLegacyPlaneFixtureParsesAndIsComplete(t *testing.T) {
	rows, err := ParseLegacyPlanes(LegacyPlaneFile)
	if err != nil {
		t.Fatalf("parsing the legacy plane table: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("the table has no rows")
	}
	declaredEmpty, advertising := 0, 0
	for _, r := range rows {
		if !r.Edition.IsValid() {
			t.Errorf("line %d declares edition %s", r.Line, r.Edition)
		}
		if len(r.Capabilities) == 0 {
			declaredEmpty++
			continue
		}
		advertising++
		for _, c := range r.Capabilities {
			if c.Version <= 0 {
				t.Errorf("line %d advertises %q at version %d", r.Line, c.Type, c.Version)
			}
		}
	}
	// Both shapes must occur. A table where every plane advertises something
	// would never exercise the declared-empty status, and the distinction
	// AXC-312 rests on would be asserted only against a synthetic fixture.
	if declaredEmpty == 0 {
		t.Errorf("no plane declares an empty capability set, so the fixture never exercises CapabilityDeclaredNone")
	}
	if advertising == 0 {
		t.Errorf("no plane advertises anything, so the fixture never exercises CapabilitySupported")
	}
}

// TestLegacyPlaneEvidenceNamesFilesThatExist holds every capability claim to a
// file in this repository.
//
// The claims are the part of this fixture that can quietly become false: a
// plane's redaction path is deleted, its handler is renamed, and the table
// still says it discharges the obligation. Checking the file is the coarsest
// check that cannot be satisfied by a stale memory, and it fails on the pull
// request that moves the file rather than on some later one.
//
// This module mirrors to the public community repository, and the mirror is
// produced by stripping ee/ AND every enterprise-tagged Go file (#3574). A
// cited file may therefore be absent there by construction; treating that as
// a deletion made this test red on the mirror for
// platform/agent/cowork_otel_ingest.go. The rule, in both trees:
//
//   - A community-edition row's file must exist and must not be enterprise-only
//     source: a community claim discharged by a file the community build does
//     not have is a false claim.
//   - On the mirror, an absent file is excused ONLY when the mirror can know
//     the sync stripped it (mirrorKnowsIsStripped): by the path's name, or by
//     the shipped, enterprise-verified call-site census. A row's own edition is
//     not that knowledge - enterprise-edition rows cite untagged community
//     files, and a rename of one of those on the public repository must stay a
//     finding there, not an "expected strip".
//   - In the enterprise tree every file must exist, and every file the strip
//     removes must be one the mirror can know about, or the mirror would report
//     a strip as a deletion. That keeps the mirror's excuse set equal to the
//     strip set, checked where the files are.
func TestLegacyPlaneEvidenceNamesFilesThatExist(t *testing.T) {
	rows, err := ParseLegacyPlanes(LegacyPlaneFile)
	if err != nil {
		t.Fatalf("parsing the legacy plane table: %v", err)
	}
	mirror := treeIsCommunityMirror()
	checked, stripped := 0, 0
	for _, r := range rows {
		path := r.EvidenceFile()
		if path == "" {
			t.Errorf("line %d has no file in its evidence cell %q", r.Line, r.Evidence)
			continue
		}
		full := filepath.Join(repoRoot, path)
		if _, statErr := os.Stat(full); statErr != nil {
			if mirror && mirrorKnowsIsStripped(t, path) {
				stripped++
				continue
			}
			t.Errorf("line %d cites %s, which does not exist: %v", r.Line, path, statErr)
			continue
		}
		enterpriseOnly, classErr := evidenceIsEnterpriseOnly(path)
		if classErr != nil {
			t.Fatalf("line %d: classifying %s: %v", r.Line, path, classErr)
		}
		if r.Edition == EditionCommunity && enterpriseOnly {
			t.Errorf("line %d is a community-edition row whose evidence %s is enterprise-only source; the community build cannot discharge a claim with a file it does not have", r.Line, path)
			continue
		}
		if !mirror && enterpriseOnly && !mirrorKnowsIsStripped(t, path) {
			t.Errorf("line %d cites %s, which the sync strips by its build constraint, and nothing that survives the strip says so: the mirror would report it as deleted. Cite evidence in a file the community build carries, or in a file named *_enterprise.go or under ee/", r.Line, path)
			continue
		}
		checked++
	}
	if checked == 0 {
		t.Fatalf("no evidence file was checked, so this gate asserts nothing")
	}
	if stripped > 0 {
		t.Logf("community tree: %d cited file(s) absent and known to be stripped by the sync (by name or by the shipped census)", stripped)
	}
	// Anti-vacuity: the same check has to fail on a path that is not there, so
	// a resolver that silently succeeded would be caught.
	if _, err := os.Stat(filepath.Join(repoRoot, "platform/agent/this_file_does_not_exist.go")); err == nil {
		t.Fatalf("the existence check passed on a file that should not exist")
	}
}

// TestLegacyPlanePEPsDifferByEdition proves the edition split is real and in
// the safe direction.
func TestLegacyPlanePEPsDifferByEdition(t *testing.T) {
	community, err := LegacyPlanePEPs(EditionCommunity)
	if err != nil {
		t.Fatalf("building the community records: %v", err)
	}
	enterprise, err := LegacyPlanePEPs(EditionEnterprise)
	if err != nil {
		t.Fatalf("building the Enterprise records: %v", err)
	}
	if len(community) == 0 || len(enterprise) == 0 {
		t.Fatalf("one edition produced no records: community=%d enterprise=%d", len(community), len(enterprise))
	}

	byID := func(in []PEPRecord) map[string]PEPRecord {
		out := map[string]PEPRecord{}
		for _, r := range in {
			out[r.ID] = r
		}
		return out
	}
	cm, em := byID(community), byID(enterprise)

	// No community record advertises an Enterprise-only family. This is the
	// property the whole edition axis exists for.
	enterpriseOnly := map[contract.ObligationType]bool{}
	for _, typ := range contract.AllObligationTypes() {
		family, familyErr := contract.FamilyOf(typ)
		if familyErr != nil {
			t.Fatalf("resolving the family of %q: %v", typ, familyErr)
		}
		if enterpriseOnlyFamilies[family] {
			enterpriseOnly[typ] = true
		}
	}
	for id, rec := range cm {
		for _, c := range rec.Capabilities {
			if enterpriseOnly[c.Type] {
				t.Errorf("community plane %s advertises %q, which is in an Enterprise-only family", id, c.Type)
			}
		}
	}

	// A community plane never advertises MORE than its Enterprise counterpart.
	// The other direction is legitimate: a plane whose whole file carries the
	// enterprise build constraint has no community record at all.
	for id, crec := range cm {
		erec, ok := em[id]
		if !ok {
			t.Errorf("plane %s exists on community but not on Enterprise", id)
			continue
		}
		have := map[contract.Capability]bool{}
		for _, c := range erec.Capabilities {
			have[c] = true
		}
		for _, c := range crec.Capabilities {
			if !have[c] {
				t.Errorf("community plane %s advertises %q at version %d, which its Enterprise counterpart does not",
					id, c.Type, c.Version)
			}
		}
	}

	// At least one plane is Enterprise-only, which is what makes the absent
	// record a real state rather than a hypothetical one.
	enterpriseOnlyPlanes := 0
	for id := range em {
		if _, ok := cm[id]; !ok {
			enterpriseOnlyPlanes++
		}
	}
	if enterpriseOnlyPlanes == 0 {
		t.Errorf("every plane exists in both editions, so the fixture never produces an absent record")
	}

	// An undeclared edition is refused rather than answering with one of them.
	for _, e := range []Edition{EditionUnspecified, Edition(99), Edition(-1)} {
		if _, err := LegacyPlanePEPs(e); err == nil {
			t.Errorf("Edition(%d) produced a record set", int(e))
		}
	}
}

// TestRegisteringTheLegacyPlanesProducesBothNotKnowingStates walks the fixture
// through the real registration path and asks the capability question that
// ADR-065 invariant 8 turns into a deny.
func TestRegisteringTheLegacyPlanesProducesBothNotKnowingStates(t *testing.T) {
	c := newFixtureCatalog(t)
	if err := RegisterLegacyPlanes(c, EditionCommunity); err != nil {
		t.Fatalf("registering the community planes: %v", err)
	}
	if err := c.Validate().Err(); err != nil {
		t.Fatalf("the catalog is invalid after registering the legacy planes: %v", err)
	}

	approval := obligation(contract.ObApprovalChallenge, 1, true)

	// A plane that exists on community but cannot discharge an approval.
	held := c.SupportsObligation(LegacyPlanePEPPrefix+"wcp", approval)
	if held.Supported() {
		t.Fatalf("a community workflow plane advertised an approval challenge: %#v", held)
	}
	if held.Status != CapabilityTypeUnsupported {
		t.Fatalf("a community workflow plane answered %s", held.Status)
	}

	// A plane whose whole file is Enterprise-only: no record at all.
	absent := c.SupportsObligation(LegacyPlanePEPPrefix+"cowork_ingest", approval)
	if absent.Status != CapabilityNoRecord {
		t.Fatalf("the cowork ingest plane answered %s on a community build, expected no record", absent.Status)
	}

	// A simulation surface: registered, and declares it discharges nothing.
	none := c.SupportsObligation(LegacyPlanePEPPrefix+"policy_simulation",
		obligation(contract.ObImmutableAudit, 1, true))
	if none.Status != CapabilityDeclaredNone {
		t.Fatalf("the simulation surface answered %s, expected a declared-empty set", none.Status)
	}

	// On Enterprise the workflow plane can discharge it, so the community
	// answer above is a fact about the edition rather than about the fixture.
	ent := newFixtureCatalog(t)
	if err := RegisterLegacyPlanes(ent, EditionEnterprise); err != nil {
		t.Fatalf("registering the Enterprise planes: %v", err)
	}
	if got := ent.SupportsObligation(LegacyPlanePEPPrefix+"wcp", approval); !got.Supported() {
		t.Fatalf("the Enterprise workflow plane could not discharge an approval: %#v", got)
	}
	if got := ent.SupportsObligation(LegacyPlanePEPPrefix+"cowork_ingest",
		obligation(contract.ObFieldRedact, 1, true)); !got.Supported() {
		t.Fatalf("the Enterprise cowork ingest plane could not discharge a redaction: %#v", got)
	}
}

// TestLegacyPlaneTableRejectsAMalformedRow drives the parser over every defect
// it claims to catch, so a rule that stopped matching is caught here.
func TestLegacyPlaneTableRejectsAMalformedRow(t *testing.T) {
	clean := LegacyPlaneFile
	if _, err := ParseLegacyPlanes(clean); err != nil {
		t.Fatalf("the committed table does not parse, so the mutations below prove nothing: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(string) string
		want   string
	}{
		"a reordered header": {
			mutate: func(s string) string {
				lines := strings.Split(s, "\n")
				cells := strings.Split(lines[0], "\t")
				cells[0], cells[1] = cells[1], cells[0]
				lines[0] = strings.Join(cells, "\t")
				return strings.Join(lines, "\n")
			},
			want: "header column 1",
		},
		"a dropped column": {
			mutate: func(s string) string {
				lines := strings.Split(s, "\n")
				cells := strings.Split(lines[1], "\t")
				lines[1] = strings.Join(cells[:len(cells)-1], "\t")
				return strings.Join(lines, "\n")
			},
			want: "columns, expected",
		},
		"a blank capability cell": {
			mutate: func(s string) string { return replaceTableCell(s, 1, 2, "") },
			want:   "is empty",
		},
		"a padded cell": {
			mutate: func(s string) string { return replaceTableCell(s, 1, 1, " community") },
			want:   "surrounding whitespace",
		},
		"an undeclared edition": {
			mutate: func(s string) string { return replaceTableCell(s, 1, 1, "trial") },
			want:   "is not a declared member",
		},
		"an undeclared obligation type": {
			mutate: func(s string) string { return replaceTableCell(s, 1, 2, "invented@1") },
			want:   "the contract does not declare",
		},
		"a capability with no version": {
			mutate: func(s string) string { return replaceTableCell(s, 1, 2, "immutable_audit") },
			want:   "not of the form type@version",
		},
		"a non-positive version": {
			mutate: func(s string) string { return replaceTableCell(s, 1, 2, "immutable_audit@0") },
			want:   "version 0",
		},
		"evidence with no symbol": {
			mutate: func(s string) string { return replaceTableCell(s, 1, 3, "platform/agent/run.go") },
			want:   "path::Symbol",
		},
		"a repeated plane and edition": {
			mutate: func(s string) string {
				lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
				return strings.Join(append(lines, lines[1]), "\n")
			},
			want: "repeats plane",
		},
	} {
		t.Run("the parser refuses "+name, func(t *testing.T) {
			_, err := ParseLegacyPlanes(tc.mutate(clean))
			if err == nil {
				t.Fatalf("the parser accepted %s", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the parser refused %s with the wrong message: %v", name, err)
			}
		})
	}
}

func replaceTableCell(content string, line, col int, value string) string {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	cells := strings.Split(lines[line], "\t")
	cells[col] = value
	lines[line] = strings.Join(cells, "\t")
	return strings.Join(lines, "\n")
}
