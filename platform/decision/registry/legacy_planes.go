package registry

import (
	_ "embed"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"axonflow/platform/decision/contract"
)

// LegacyPlaneFile is the checked-in view of the legacy enforcement planes as
// registered enforcement points, embedded so the tests read the artifact that
// ships rather than a copy on the runner's disk.
//
//go:embed legacy_plane_peps.tsv
var LegacyPlaneFile string

// LegacyPlaneRealm is the trust realm the in-process legacy planes
// authenticate as.
//
// They are one realm rather than twelve because they are one service identity:
// every plane in this table runs inside the agent or the orchestrator and
// presents that process's credential. A realm per plane would claim a trust
// boundary between them that does not exist, and a policy scoped to it would
// be enforcing something the deployment cannot separate.
const LegacyPlaneRealm = "axonflow_platform"

// LegacyPlanePEPPrefix prefixes a plane's enforcement point identifier, so a
// plane identifier and an enforcement point identifier cannot be confused for
// one another in a log line or a capability refusal.
const LegacyPlanePEPPrefix = "plane:"

// legacyPlaneHeader is the exact expected header row.
var legacyPlaneHeader = []string{"plane", "edition", "capabilities", "evidence"}

// LegacyPlaneRow is one plane at one edition.
type LegacyPlaneRow struct {
	// Plane is the enforcement plane identifier, matching the vocabulary the
	// shadow-diff harness declares. The two are compared by a test rather than
	// derived from one another, because this package is the decision core's
	// registry and the shadow harness is a migration tool: a build dependency
	// from the first on the second would outlive the migration.
	Plane string
	// Edition is the build this row describes.
	Edition Edition
	// Capabilities are the obligations this plane discharges ITSELF. An
	// obligation it forwards to a downstream enforcement point is that point's
	// capability, not this one's.
	Capabilities []contract.Capability
	// Evidence is the file and symbol behind the claim, in the
	// "path::Symbol" form the audit-coverage allowlist uses.
	Evidence string
	// Line is the one-based line number, for error messages.
	Line int
}

// EvidenceFile returns the repository-relative path from the evidence cell.
func (r LegacyPlaneRow) EvidenceFile() string {
	path, _, found := strings.Cut(r.Evidence, "::")
	if !found {
		return ""
	}
	return path
}

// PEPID is the enforcement point identifier for this plane.
func (r LegacyPlaneRow) PEPID() string { return LegacyPlanePEPPrefix + r.Plane }

// ParseLegacyPlanes parses the checked-in table.
//
// It is strict about shape for the same reason the disposition ledger is: a
// shifted column has to be a parse error rather than a value landing quietly
// in the wrong field. An empty capability list is the literal "-" and never an
// empty cell, so "this plane discharges nothing" is something somebody wrote
// rather than something a blank cell was read as.
func ParseLegacyPlanes(content string) ([]LegacyPlaneRow, error) {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("registry: the legacy plane table has no data rows")
	}
	header := strings.Split(lines[0], "\t")
	if len(header) != len(legacyPlaneHeader) {
		return nil, fmt.Errorf("registry: the legacy plane table header has %d columns, expected %d",
			len(header), len(legacyPlaneHeader))
	}
	for i, want := range legacyPlaneHeader {
		if header[i] != want {
			return nil, fmt.Errorf("registry: the legacy plane table header column %d is %q, expected %q",
				i+1, header[i], want)
		}
	}
	var out []LegacyPlaneRow
	seen := map[string]int{}
	for n, line := range lines[1:] {
		lineNo := n + 2
		cells := strings.Split(line, "\t")
		if len(cells) != len(legacyPlaneHeader) {
			return nil, fmt.Errorf("registry: legacy plane table line %d has %d columns, expected %d",
				lineNo, len(cells), len(legacyPlaneHeader))
		}
		for i, c := range cells {
			if c == "" {
				return nil, fmt.Errorf("registry: legacy plane table line %d column %q is empty; an empty capability list is written as \"-\"",
					lineNo, legacyPlaneHeader[i])
			}
			if strings.TrimSpace(c) != c {
				return nil, fmt.Errorf("registry: legacy plane table line %d column %q has surrounding whitespace",
					lineNo, legacyPlaneHeader[i])
			}
		}
		edition, err := parseEdition(cells[1])
		if err != nil {
			return nil, fmt.Errorf("registry: legacy plane table line %d: %w", lineNo, err)
		}
		caps, err := parseCapabilityList(cells[2])
		if err != nil {
			return nil, fmt.Errorf("registry: legacy plane table line %d: %w", lineNo, err)
		}
		if !strings.Contains(cells[3], "::") {
			return nil, fmt.Errorf("registry: legacy plane table line %d evidence %q is not of the form path::Symbol",
				lineNo, cells[3])
		}
		key := cells[0] + "/" + cells[1]
		if prev, dup := seen[key]; dup {
			return nil, fmt.Errorf("registry: legacy plane table line %d repeats plane %q at edition %q, first declared on line %d",
				lineNo, cells[0], cells[1], prev)
		}
		seen[key] = lineNo
		out = append(out, LegacyPlaneRow{
			Plane: cells[0], Edition: edition, Capabilities: caps, Evidence: cells[3], Line: lineNo,
		})
	}
	return out, nil
}

func parseEdition(s string) (Edition, error) {
	for _, e := range AllEditions() {
		if e.String() == s {
			return e, nil
		}
	}
	return EditionUnspecified, fmt.Errorf("edition %q is not a declared member", s)
}

// parseCapabilityList parses "type@version,type@version" or the literal "-".
func parseCapabilityList(cell string) ([]contract.Capability, error) {
	if cell == "-" {
		// An explicitly empty set, which is a declaration and not an absence.
		// It is returned as a non-nil empty slice so a caller that
		// round-trips it through JSON cannot turn "declares nothing" back
		// into "declared nothing at all".
		return []contract.Capability{}, nil
	}
	declared := map[contract.ObligationType]bool{}
	for _, t := range contract.AllObligationTypes() {
		declared[t] = true
	}
	var out []contract.Capability
	for _, part := range strings.Split(cell, ",") {
		name, version, found := strings.Cut(part, "@")
		if !found {
			return nil, fmt.Errorf("capability %q is not of the form type@version", part)
		}
		v, err := strconv.Atoi(version)
		if err != nil {
			return nil, fmt.Errorf("capability %q declares a non-numeric version: %w", part, err)
		}
		if v <= 0 {
			return nil, fmt.Errorf("capability %q declares version %d; matching is exact, so a non-positive version matches only an obligation whose version was never set", part, v)
		}
		if !declared[contract.ObligationType(name)] {
			return nil, fmt.Errorf("capability %q names obligation type %q, which the contract does not declare", part, name)
		}
		out = append(out, contract.Capability{Type: contract.ObligationType(name), Version: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}

// LegacyPlanePEPs returns the enforcement point records for one edition.
//
// A plane ABSENT from the returned set is absent because it does not exist in
// that build: the cowork ingest plane's whole file carries the enterprise build
// constraint, so a community deployment has no such enforcement point rather
// than one that discharges nothing. That distinction is exactly the one
// CapabilityStatus keeps: NoRecord and DeclaredNone are different answers, and
// this fixture produces both from real deployments rather than from a
// synthetic case.
func LegacyPlanePEPs(edition Edition) ([]PEPRecord, error) {
	if !edition.IsValid() {
		return nil, fmt.Errorf("registry: edition %s is not a declared member", edition)
	}
	rows, err := ParseLegacyPlanes(LegacyPlaneFile)
	if err != nil {
		return nil, err
	}
	var out []PEPRecord
	for _, r := range rows {
		if r.Edition != edition {
			continue
		}
		out = append(out, PEPRecord{
			ID:           r.PEPID(),
			Realm:        LegacyPlaneRealm,
			Edition:      edition,
			Capabilities: r.Capabilities,
			Description: fmt.Sprintf("legacy %s enforcement plane, %s build; capability evidence: %s",
				r.Plane, edition, r.Evidence),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// RegisterLegacyPlanes registers the legacy planes as enforcement points on a
// catalog, declaring their realm first.
func RegisterLegacyPlanes(c *Catalog, edition Edition) error {
	records, err := LegacyPlanePEPs(edition)
	if err != nil {
		return err
	}
	if !c.RealmDeclared(LegacyPlaneRealm) {
		if err := c.RegisterRealm(LegacyPlaneRealm); err != nil {
			return err
		}
	}
	for _, r := range records {
		if err := c.RegisterPEP(r); err != nil {
			return err
		}
	}
	return nil
}
