// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
)

//go:embed registry.json
var registryJSON []byte

// registry is the parsed embedded registry.
//
// It is parsed and self-validated at package initialisation and PANICS on
// failure. That is deliberate. The file is embedded at compile time, so a
// failure here is a broken binary rather than a runtime condition, and both
// planes' /health responses are projected from it — a health endpoint that
// answers with a silently degraded capability list is worse than one that does
// not answer at all, because an orchestrator reads the degraded answer as
// success and an SDK reads a missing capability as "not supported".
// TestEmbeddedRegistryIsValid makes the panic unreachable in a shipped build.
var registry = mustParse(registryJSON)

func mustParse(b []byte) *Registry {
	r, err := Parse(b)
	if err != nil {
		panic("capability: the embedded registry is unusable: " + err.Error())
	}
	return r
}

// Load returns the embedded registry. The returned pointer is shared; callers
// must not mutate it.
func Load() *Registry { return registry }

// Parse decodes and validates a registry document.
func Parse(b []byte) (*Registry, error) {
	var r Registry
	dec := json.NewDecoder(bytes.NewReader(b))
	// An unknown field is a schema mismatch, not a harmless extra: a field
	// renamed in the schema and left behind in the file would otherwise be
	// read as "absent" while the file plainly states a value for it.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("decoding the registry: %w", err)
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Problems is an ordered list of validation failures. Every failure is
// collected rather than returning on the first, because a census is edited in
// bulk and one error per run turns a ten-minute fix into ten CI rounds.
type Problems []string

func (p Problems) Error() string {
	return fmt.Sprintf("the capability registry has %d problem(s):\n  - %s",
		len(p), strings.Join(p, "\n  - "))
}

// Validate checks the registry against itself: the vocabularies, the internal
// consistency rules, and the fields that may not be empty. It touches no
// files, so it runs identically in a shipped binary and in a test.
//
// The five failure classes #3590 requires are all here — duplicate IDs, a
// missing owner, contradictory source classifications, an unknown edition, and
// (in Registry.CheckCoverage, which needs the tree) a derived capability with
// no entry.
func (r *Registry) Validate() error {
	var p Problems
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }

	if r.Schema != SchemaVersion {
		add("schema is %q, but this reader implements %q; a file written for another schema "+
			"must not be read field-by-field as if the fields still meant the same thing",
			r.Schema, SchemaVersion)
		// Every check below is about fields whose meaning the schema fixes, so
		// reporting them against a mismatched schema would be noise.
		return p
	}
	if r.Platform == "" {
		add("platform_version is empty: a census with no platform version cannot be compared " +
			"with the release it describes")
	}
	if r.Generated == "" {
		add("generated is empty")
	}
	if len(r.Entries) == 0 {
		add("the registry has no capabilities, which would make every coverage check below " +
			"pass vacuously")
		return p
	}
	if len(r.ScanRoots) == 0 {
		add("scan_roots is empty: the derivation would walk nothing and every coverage check " +
			"would pass on an empty inventory")
	}

	seenID := map[string]int{}
	seenHealthName := map[string]int{}
	healthOrder := map[string]map[int]string{}

	for i, e := range r.Entries {
		where := fmt.Sprintf("entry %d (%s)", i, orUnnamed(e.ID))

		// --- identity ------------------------------------------------------
		if e.ID == "" {
			add("%s: id is empty", where)
		} else if prev, dup := seenID[e.ID]; dup {
			add("duplicate capability id %q: entries %d and %d. Two rows for one id means "+
				"every lookup by id silently reads whichever came first", e.ID, prev, i)
		} else {
			seenID[e.ID] = i
		}
		if !idPattern(e.ID) {
			add("%s: id %q is not lower snake case dotted (family.name)", where, e.ID)
		}
		if e.Family == "" {
			add("%s: family is empty", where)
		} else if e.ID != "" && !strings.HasPrefix(e.ID, e.Family+".") {
			add("%s: id %q does not start with its family %q; the family is what the band "+
				"scoring groups by, so a mismatch scores the capability under a family it "+
				"does not name", where, e.ID, e.Family)
		}
		if e.Title == "" {
			add("%s: title is empty", where)
		}
		if e.Summary == "" {
			add("%s: summary is empty", where)
		}

		// --- vocabularies ---------------------------------------------------
		if !ValidEdition(e.MinimumEdition) {
			add("%s: unknown minimum_edition %q (want one of %v). There is no encoding for "+
				"an undecided edition: an unclassified capability must fail, not pass as a "+
				"blank", where, e.MinimumEdition, Editions())
		}
		if !ValidClassification(e.Classification) {
			add("%s: unknown source_classification %q (want one of %v)",
				where, e.Classification, Classifications())
		}
		if !validBuildTag[e.BuildTag] {
			add("%s: unknown build_tag %q", where, e.BuildTag)
		}
		if !validSync[e.Sync] {
			add("%s: unknown sync %q", where, e.Sync)
		}

		// --- cross-field consistency ----------------------------------------
		if ValidEdition(e.MinimumEdition) && ValidClassification(e.Classification) {
			floor := MinimumEditionFor(e.Classification)
			if editionRank[e.MinimumEdition] < editionRank[floor] {
				add("%s: contradictory classification — source_classification %q keeps the "+
					"implementation out of a Community build, so it cannot have "+
					"minimum_edition %q; the least edition that can run it is %q",
					where, e.Classification, e.MinimumEdition, floor)
			}
		}
		if e.Classification == ClassEnterpriseImplementation && e.BuildTag == TagNone {
			add("%s: contradictory classification — source_classification is %q, which ADR-066 "+
				"decision 5 defines as source that exists only under ee/ or an enterprise "+
				"build constraint, but build_tag is %q", where, e.Classification, e.BuildTag)
		}
		if e.Classification == ClassEnterpriseImplementation && e.Sync == SyncMirrored {
			add("%s: contradictory classification — %q source must not reach the community "+
				"mirror, but sync is %q", where, e.Classification, e.Sync)
		}
		// The REVERSE rules. Every rule above is keyed on the classification
		// being enterprise_implementation, so an entry laundered INTO the
		// community column - community_core, build_tag none, sync mirrored -
		// satisfies all of them by being none of them. These three close that
		// direction on facts the document itself carries;
		// TestEditionFactsMatchTheTree closes it on the facts only the tree
		// carries, which is the half that cannot be edited.
		if e.BuildTag == TagEnterprise {
			if e.Sync == SyncMirrored {
				add("%s: build_tag is %q and sync is %q, which is not a state that can "+
					"exist: the sync deletes every enterprise-tagged file before it "+
					"publishes", where, e.BuildTag, e.Sync)
			}
			if e.Classification == ClassCommunityCore || e.Classification == ClassEvaluationPreview {
				add("%s: build_tag is %q, so no part of this capability compiles into a "+
					"Community build, but source_classification is %q, which says the "+
					"implementation may sync publicly", where, e.BuildTag, e.Classification)
			}
			if e.MinimumEdition == EditionCommunity || e.MinimumEdition == EditionEvaluation {
				add("%s: build_tag is %q, so the implementation is absent from a Community "+
					"build, but minimum_edition is %q", where, e.BuildTag, e.MinimumEdition)
			}
		}
		if e.Classification == ClassCommunityCore && e.Sync == SyncExcluded {
			add("%s: contradictory classification — %q means the complete implementation may "+
				"sync publicly, but sync is %q", where, e.Classification, e.Sync)
		}

		// --- owner ----------------------------------------------------------
		if e.Owner == "" {
			add("%s: owner is empty. ADR-066 conformance item 10 requires every capability to "+
				"be exercised by a named test; an unowned capability is one nothing is known "+
				"to run", where)
		} else if !strings.HasSuffix(e.Owner, "_test.go") && !strings.HasSuffix(e.Owner, ".sh") {
			add("%s: owner %q is neither a Go test file nor a shell suite", where, e.Owner)
		}
		if len(e.Implementation) == 0 {
			add("%s: implementation is empty", where)
		}
		for _, path := range e.Implementation {
			if strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
				add("%s: implementation path %q must be repo-relative", where, path)
			}
		}

		// --- routes -----------------------------------------------------------
		if len(e.Routes) > 0 && len(e.Planes) == 0 {
			add("%s: %d route(s) but no plane; a route nobody serves cannot be reached",
				where, len(e.Routes))
		}
		for _, rt := range e.Routes {
			if !strings.HasPrefix(rt, "/") {
				add("%s: route %q does not start with /", where, rt)
			}
		}

		// --- health -----------------------------------------------------------
		switch {
		case e.Health == nil && e.HealthAbsentReason == "":
			add("%s: not advertised on /health and no health_absent_reason. Absence from a "+
				"DISCOVERY surface reads to an SDK as \"not supported\", so it has to be a "+
				"recorded decision rather than a default", where)
		case e.Health != nil && e.HealthAbsentReason != "":
			add("%s: has both a health block and a health_absent_reason", where)
		case e.Health != nil:
			if e.HealthGap {
				add("%s: health_gap is set on a capability that IS advertised; the field "+
					"marks an absence that is arguably wrong, and there is no absence here",
					where)
			}
			h := e.Health
			if h.Name == "" {
				add("%s: health.name is empty", where)
			} else if prev, dup := seenHealthName[h.Name]; dup {
				add("duplicate /health capability name %q: entries %d and %d. The served list "+
					"would carry it twice", h.Name, prev, i)
			} else {
				seenHealthName[h.Name] = i
			}
			if h.Since == "" {
				add("%s: health.since is empty", where)
			}
			if h.Description == "" {
				add("%s: health.description is empty", where)
			}
			if len(h.Planes) == 0 {
				add("%s: health.planes is empty, so the entry is advertised nowhere while "+
					"claiming to be advertised", where)
			}
			for pl, over := range h.DescriptionOverrides {
				if !contains(h.Planes, pl) {
					add("%s: health.description_overrides names plane %q, which is not "+
						"in health.planes, so the override is served nowhere", where, pl)
				}
				if strings.TrimSpace(over) == "" {
					add("%s: health.description_overrides[%q] is empty; an override that "+
						"blanks the description is a wire regression, not an override",
						where, pl)
				}
			}
			for _, pl := range h.Planes {
				if pl != PlaneAgent && pl != PlaneOrchestrator {
					add("%s: health.planes has %q; /health is served by %q and %q only",
						where, pl, PlaneAgent, PlaneOrchestrator)
					continue
				}
				if healthOrder[pl] == nil {
					healthOrder[pl] = map[int]string{}
				}
				if prev, clash := healthOrder[pl][h.Order]; clash {
					add("/health order %d on plane %q is claimed by both %q and %q; the served "+
						"list is a wire artifact whose order clients have observed, so it must "+
						"be total", h.Order, pl, prev, h.Name)
				} else {
					healthOrder[pl][h.Order] = h.Name
				}
			}
		}

		if e.MatrixDisagreement != "" && !ValidDisagreement(e.MatrixDisagreement) {
			add("%s: unknown matrix_disagreement %q (want one of %v). It classifies the "+
				"disagreement; the narrative lives in the census, off the mirror",
				where, e.MatrixDisagreement, Disagreements())
		}

		// --- score -------------------------------------------------------------
		p = append(p, validateScore(where, e)...)
	}

	p = append(p, r.validateRoutePrefixesAreUnambiguous()...)
	p = append(p, r.validateExemptions()...)
	p = append(p, r.validateMatrixSections()...)

	// Sorted, because several of the checks above iterate maps and Go
	// randomises that order. Two runs over one broken file would otherwise
	// print the same problems in a different order, and a CI failure nobody can
	// diff against the last one is a failure people stop reading.
	sort.Strings(p)
	if len(p) > 0 {
		return p
	}
	return nil
}

// validateMatrixSections checks the two matrix-facing lists for the empties and
// duplicates that would make the reconciliation quietly weaker.
func (r *Registry) validateMatrixSections() Problems {
	var p Problems
	for _, e := range r.Entries {
		seen := map[string]bool{}
		for _, h := range e.Matrix {
			switch {
			case strings.TrimSpace(h) == "":
				p = append(p, fmt.Sprintf("%s: an empty matrix heading", e.ID))
			case seen[h]:
				p = append(p, fmt.Sprintf("%s: matrix heading %q listed twice", e.ID, h))
			}
			seen[h] = true
		}
	}
	seen := map[string]bool{}
	for _, sec := range r.MatrixSectionsOutOfScope {
		if strings.TrimSpace(sec.Heading) == "" {
			p = append(p, "a matrix_sections_out_of_scope entry has an empty heading")
			continue
		}
		if seen[sec.Heading] {
			p = append(p, fmt.Sprintf("matrix section %q is declared out of scope twice",
				sec.Heading))
		}
		seen[sec.Heading] = true
		if strings.TrimSpace(sec.Reason) == "" {
			p = append(p, fmt.Sprintf("matrix section %q is declared out of scope with no "+
				"reason. An exclusion without a reason is an omission with a nicer name",
				sec.Heading))
		}
	}
	return p
}

func validateScore(where string, e Entry) Problems {
	var p Problems
	add := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }
	s := e.Score
	if !validBasis[s.Basis] {
		add("%s: unknown score.basis %q (want one of MEASURED, CHOSEN, UNSCORABLE)", where, s.Basis)
		return p
	}
	if s.Basis != BasisMeasured && strings.TrimSpace(s.Reason) == "" {
		add("%s: score.basis is %s and score.reason is empty. A figure that is not read off "+
			"the tree has to say what the judgement was, or the next reader cannot tell it "+
			"from a measurement", where, s.Basis)
	}
	if s.Basis == BasisUnscorable {
		// An unscorable capability states no availabilities: a value here would
		// be counted by some future reader that forgot to check the basis.
		for name, a := range map[string]Availability{
			"community": s.Community, "evaluation": s.Evaluation, "enterprise": s.Enterprise,
		} {
			if a != "" {
				add("%s: score.basis is UNSCORABLE but score.%s is %q; an unscorable "+
					"capability carries no availability rather than a placeholder one",
					where, name, a)
			}
		}
		return p
	}
	for name, a := range map[string]Availability{
		"community": s.Community, "evaluation": s.Evaluation, "enterprise": s.Enterprise,
	} {
		if _, ok := a.Weight(); !ok {
			add("%s: unknown score.%s %q (want full, limited or none)", where, name, a)
		}
	}
	cw, cok := s.Community.Weight()
	ev, eok := s.Evaluation.Weight()
	en, enok := s.Enterprise.Weight()
	if cok && eok && enok {
		// Entitlement is monotonic by construction: every higher tier maps onto
		// the limits of the one below plus its own. A score that says otherwise
		// is either a typo or a real defect in the gating, and both need seeing.
		if cw > ev || ev > en {
			add("%s: score is not monotonic across editions (community=%s, evaluation=%s, "+
				"enterprise=%s). Either the row is wrong or the shipped gating gives a lower "+
				"edition more than a higher one, which is a defect to route rather than to "+
				"encode", where, s.Community, s.Evaluation, s.Enterprise)
		}
		if ValidEdition(e.MinimumEdition) {
			// The two axes must agree at the floor: a capability whose minimum
			// edition is enterprise cannot be scored as present in community.
			switch e.MinimumEdition {
			case EditionEnterprise:
				if cw > 0 || ev > 0 {
					add("%s: minimum_edition is %q but the score gives it to a lower edition "+
						"(community=%s, evaluation=%s)", where, e.MinimumEdition,
						s.Community, s.Evaluation)
				}
			case EditionEvaluation:
				if cw > 0 {
					add("%s: minimum_edition is %q but score.community is %s",
						where, e.MinimumEdition, s.Community)
				}
			case EditionCommunity:
				if cw == 0 {
					add("%s: minimum_edition is %q but score.community is %s; a capability no "+
						"Community deployment has does not have a Community minimum",
						where, e.MinimumEdition, s.Community)
				}
			}
		}
	}
	if s.Community == AvailLimited && len(e.LicenseGate) == 0 && strings.TrimSpace(e.Notes) == "" {
		add("%s: score.community is %q but no license_gate and no notes name the cap. "+
			"\"limited\" with nothing naming the limit is an unfalsifiable half-mark",
			where, AvailLimited)
	}
	return p
}

func (r *Registry) validateExemptions() Problems {
	var p Problems
	seen := map[string]bool{}
	for _, x := range r.RouteExemptions {
		if x.Pattern == "" {
			p = append(p, "a route_exemption has an empty pattern")
			continue
		}
		if seen[x.Pattern] {
			p = append(p, fmt.Sprintf("duplicate route_exemption %q", x.Pattern))
		}
		seen[x.Pattern] = true
		p = append(p, validateExemptionReason(x)...)
		p = append(p, r.validateExemptionCitations(x)...)
	}
	return p
}

func orUnnamed(s string) string {
	if s == "" {
		return "no id"
	}
	return s
}

// idPattern reports whether id is `family.name` in lower snake case. Written
// without regexp so the rule is readable at the point it is enforced.
func idPattern(id string) bool {
	if id == "" {
		return false
	}
	parts := strings.Split(id, ".")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for i := 0; i < len(part); i++ {
			c := part[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}

// ValidateAgainstTree runs the checks that need the repository: that every
// owner test and every implementation path named by an entry actually exists.
//
// It is separate from Validate because Validate has to run inside a shipped
// binary, where there is no repository to look at.
//
// It is edition-aware, and has to be. The community mirror strips source two
// ways — `ee/` wholesale and the enterprise half of every build-tag pair — so
// on a mirror checkout the implementation paths of an excluded capability are
// legitimately missing, and asserting their presence there would fail the
// public repository's own test job for doing exactly what the sync workflow is
// designed to do. Paths belonging to an entry whose sync is `excluded` or
// `stub` are therefore checked only in a tree that still has `ee/`, which is
// the enterprise repository and nothing else. Everything else is checked
// unconditionally, in both trees.
func (r *Registry) ValidateAgainstTree(root string) error {
	var p Problems
	_, eeErr := os.Stat(filepath.Join(root, "ee"))
	enterpriseTree := eeErr == nil

	for _, e := range r.Entries {
		strippedHere := !enterpriseTree && e.Sync != SyncMirrored
		check := func(kind, path string) {
			if path == "" {
				return
			}
			if _, err := os.Stat(filepath.Join(root, path)); err == nil {
				return
			}
			if strippedHere {
				return
			}
			p = append(p, fmt.Sprintf("%s: %s %q does not exist", e.ID, kind, path))
		}
		check("owner", e.Owner)
		for _, impl := range e.Implementation {
			check("implementation", impl)
		}
	}
	sort.Strings(p)
	if len(p) > 0 {
		return p
	}
	return nil
}

// CapabilityForRoute returns the entry that owns a route pattern, or nil.
//
// LONGEST PREFIX WINS, and that is a deliberate choice rather than a
// convenience. Capability families nest: /api/v1/workflows is the workflow
// control plane, /api/v1/workflows/{id}/checkpoints is the checkpoint
// capability, and both statements are true of the same URL. Attributing the
// route to the broadest match would file every checkpoint route under the
// lifecycle capability and make the census's per-capability route counts
// meaningless; attributing it to the narrowest one gives each route exactly one
// owner and keeps the broad family's own routes with the family.
//
// Two entries claiming the IDENTICAL prefix is a different thing entirely — a
// genuine ambiguity with no right answer — and Validate rejects it.
func (r *Registry) CapabilityForRoute(route string) *Entry {
	var best *Entry
	bestLen := -1
	for i := range r.Entries {
		for _, prefix := range r.Entries[i].Routes {
			if !routeCoveredBy(prefix, route) {
				continue
			}
			if len(prefix) > bestLen {
				best, bestLen = &r.Entries[i], len(prefix)
			}
		}
	}
	return best
}

// routeCoveredBy reports whether prefix covers route.
//
// The trailing separator is what stops /api/v1/policies from swallowing
// /api/v1/policy-overrides: a prefix covers a route only when the route IS the
// prefix or continues it at a path boundary. A bare strings.HasPrefix would
// attribute the second to the first and report coverage of a capability that
// has nothing to do with it.
func routeCoveredBy(prefix, route string) bool {
	if route == prefix {
		return true
	}
	trimmed := strings.TrimSuffix(prefix, "/")
	return strings.HasPrefix(route, trimmed+"/")
}

// validateRoutePrefixesAreUnambiguous rejects two entries claiming the same
// route prefix. Longest-prefix attribution resolves NESTED claims; it cannot
// resolve identical ones, and picking whichever came first would make the
// census's ownership of that route an artifact of file order.
func (r *Registry) validateRoutePrefixesAreUnambiguous() Problems {
	var p Problems
	owner := map[string]string{}
	for _, e := range r.Entries {
		seen := map[string]bool{}
		for _, prefix := range e.Routes {
			if seen[prefix] {
				p = append(p, fmt.Sprintf("%s lists route %q twice", e.ID, prefix))
				continue
			}
			seen[prefix] = true
			if prev, dup := owner[prefix]; dup {
				p = append(p, fmt.Sprintf("route %q is claimed by both %s and %s; "+
					"longest-prefix attribution cannot separate two identical claims",
					prefix, prev, e.ID))
				continue
			}
			owner[prefix] = e.ID
		}
	}
	return p
}

// nonReasons are the things people write when they have no reason.
var nonReasons = []string{
	"n/a", "na", "tbd", "todo", "wip", "see above", "see below", "as discussed",
	"not applicable", "obvious", "self-explanatory", "by design", "intentional",
	"known issue", "pre-existing", "legacy", "temporary", "for now", "?",
}

// validateExemptionReason refuses an exemption that carries no argument.
//
// An empty reason is easy to catch and is not the shape this fails in. The
// shape it fails in is a reason that is PRESENT and says nothing - "by design",
// "legacy", "n/a" - because that satisfies a presence check, survives review as
// a thing somebody wrote, and licenses a hole for ever.
//
// The first version applied the phrase check only under 40 characters, and R3
// broke it in one line: "by design, legacy, pre-existing, table-driven, nothing
// to add here" is 66 characters of nothing and was accepted, because PADDING
// WITH MORE NON-REASONS bought its way past a length floor. So the phrases are
// now STRIPPED and the floor applies to what is LEFT. Concatenating non-reasons
// cannot lengthen the remainder, which is the property the length check needed
// and did not have.
//
// Both halves are crude and will occasionally be wrong. That is the right
// direction to be wrong in: the cost is one reviewer writing a fuller sentence,
// against an unexamined hole in the only coverage guarantee this registry
// offers.
// capabilityIDInProse matches a `family.name` token inside an exemption reason.
//
// Deliberately narrow: lower case, digits and underscores only, exactly one
// dot. `mux.NewRouter()` and `run.go:1552` do not match, and the family gate in
// validateExemptionCitations rejects whatever else slips through.
var capabilityIDInProse = regexp.MustCompile(`\b[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*\b`)

// pathInProse matches a URL path written in an exemption reason.
var pathInProse = regexp.MustCompile(`/[a-z0-9][a-zA-Z0-9/_.:{}-]*`)

// quotedPathInPattern pulls the literal path out of an exemption key, e.g.
// `platform/agent/run.go:1552 HandleFunc(<…>"/metrics")` -> `/metrics`.
var quotedPathInPattern = regexp.MustCompile(`"(/[^"]*)"`)

// validateExemptionCitations is the FIDELITY half of the exemption rule, and it
// exists because the other half proves only consistency.
//
// An exemption's argument is always the same shape: "the scanner could not read
// this, but capability X claims the path, so the URL space is covered". Nothing
// checked that X existed. Writing seven of these by hand produced FIVE
// capability ids that do not exist in this registry — platform.health_check,
// observability.metrics, gateway.request, tenancy.clients, policy.test — and
// the only thing that stopped them shipping was looking each one up. Probing
// for a guard afterwards found none: a fabricated id reddened exactly one test,
// the census golden file, and regenerating the census made it pass. A
// regeneration gate proves the document matches the registry, never that the
// registry is true.
//
// Two rules, and the second is the one that bites:
//
//  1. any `family.name` token whose FAMILY exists must be a real capability id.
//     This catches a typo or a drifted rename inside a family that is real.
//  2. when the exemption key carries a literal path, some capability the reason
//     names must actually CLAIM that path in its routes. This is what ties the
//     prose to the coverage it asserts: an exemption may cite three real ids and
//     still cover nothing.
//
// Rule 1 alone would have missed gateway.request and tenancy.clients, whose
// families do not exist either; rule 2 catches every one of the five.
func (r *Registry) validateExemptionCitations(x RouteExemption) Problems {
	var p Problems
	families := map[string]bool{}
	byID := map[string]*Entry{}
	for i := range r.Entries {
		e := &r.Entries[i]
		families[e.Family] = true
		byID[e.ID] = e
	}

	var named []*Entry
	for _, tok := range capabilityIDInProse.FindAllString(x.Reason, -1) {
		e, isID := byID[tok]
		if isID {
			named = append(named, e)
			continue
		}
		if families[strings.SplitN(tok, ".", 2)[0]] {
			p = append(p, fmt.Sprintf("route_exemption %q cites capability %q, which does "+
				"not exist. Its FAMILY does, so this is a typo or a rename nobody followed "+
				"— and an exemption that names a capability which is not there asserts a "+
				"coverage that nothing provides", x.Pattern, tok))
		}
	}

	// RULE 3, AND IT IS UNCONDITIONAL. Every exemption must name at least one
	// capability that EXISTS.
	//
	// This is the rule the first version was missing, and the gap was found by
	// pointing the guard at its own subject. On a key with no literal path
	// rule 2 returned early, and rule 1 is blind to an invented id whose
	// FAMILY does not exist either — so replacing the one pathless row's
	// `policy.system` with `gateway.request`, one of the five ids that were
	// actually invented on the first draft, passed the whole suite. The exact
	// input the guard exists to catch survived on a shipped row.
	//
	// An exemption's entire argument is "capability X covers this path". A row
	// naming no real capability is not making that argument.
	if len(named) == 0 {
		p = append(p, fmt.Sprintf("route_exemption %q names no capability that exists in "+
			"this registry. An exemption's whole argument is that some entry covers the "+
			"URL space the scanner could not attribute; without a real id the argument is "+
			"prose, and the id is the only part of it a machine can check", x.Pattern))
	}

	// RULE 4: any path quoted in the PROSE must be one this registry knows.
	//
	// Rule 2 checks the key's path, so a wrong path in the reason cannot cause
	// a false coverage claim — but it can mislead a reader into believing a
	// route is covered that is not, and these reasons get lifted into the
	// census verbatim. A quoted path is legitimate when it is the key's own,
	// or a route of a capability the reason names.
	if m := quotedPathInPattern.FindStringSubmatch(x.Pattern); m != nil {
		known := map[string]bool{m[1]: true}
		for _, e := range named {
			for _, rt := range e.Routes {
				known[rt] = true
			}
		}
		for _, cand := range pathInProse.FindAllString(x.Reason, -1) {
			cand = strings.TrimRight(cand, ".,;:)")
			if !known[cand] {
				p = append(p, fmt.Sprintf("route_exemption %q quotes path %q, which is "+
					"neither the path it exempts nor a route of any capability it names. "+
					"These reasons are lifted into the census verbatim, so a path here "+
					"that nothing claims reads as covered", x.Pattern, cand))
			}
		}
	}

	m := quotedPathInPattern.FindStringSubmatch(x.Pattern)
	if m == nil {
		// No literal path in the key (a struct-field argument, say). Rules 1,
		// 3 and 4 have already run; rule 2 needs a path and the FILE-scoped
		// check in the derivation test covers this row instead.
		return p
	}
	path := m[1]
	for _, e := range named {
		if slices.Contains(e.Routes, path) {
			return p
		}
	}
	got := "none at all"
	if len(named) > 0 {
		ids := make([]string, 0, len(named))
		for _, e := range named {
			ids = append(ids, e.ID)
		}
		got = strings.Join(ids, ", ")
	}
	return append(p, fmt.Sprintf("route_exemption %q says the URL space is covered, but no "+
		"capability it names claims %q. Capabilities named: %s. The argument for an "+
		"exemption is that some entry covers the path the scanner could not attribute; "+
		"naming a real capability that does not list this route is the same omission with "+
		"a citation on it", x.Pattern, path, got))
}

func validateExemptionReason(x RouteExemption) Problems {
	reason := strings.TrimSpace(x.Reason)
	if reason == "" {
		return Problems{fmt.Sprintf("route_exemption %q has no reason. An exemption without "+
			"a reason is an omission with a nicer name", x.Pattern)}
	}
	folded := strings.ToLower(reason)
	remainder := folded
	for _, nr := range nonReasons {
		remainder = strings.ReplaceAll(remainder, nr, " ")
	}
	remainder = strings.TrimSpace(strings.Join(strings.FieldsFunc(remainder, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}), " "))

	const floor = 60
	if len(remainder) < floor {
		what := "is a phrase rather than an argument"
		if len(remainder) < len(folded) {
			what = fmt.Sprintf("is %d characters of argument once the stock phrases are "+
				"removed", len(remainder))
		}
		return Problems{fmt.Sprintf("route_exemption %q %s. Say what the scanner could not "+
			"read and why the URL space is covered anyway; the floor is %d characters and "+
			"padding with more stock phrases does not raise it",
			x.Pattern, what, floor)}
	}
	return nil
}
